param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][string]$Prefix
)
$ErrorActionPreference = 'Stop'
$source = Get-Item -LiteralPath $Binary
if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Binary must be a regular, non-linked file.'
}
$binDir = [IO.Path]::GetFullPath((Join-Path $Prefix 'bin'))
[IO.Directory]::CreateDirectory($binDir) | Out-Null
$lockPath = Join-Path $binDir '.vorda-install.lock'
# FileShare None excludes a running installer; DeleteOnClose removes the file when the handle closes,
# including when the kernel closes it for a killed process. A file left by an older run is reopened.
try {
    $lock = [IO.FileStream]::new($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose)
} catch [IO.IOException] {
    [Console]::Error.WriteLine("another installation owns the install lock; if none is running, remove $lockPath")
    exit 1
}
$staged = Join-Path $binDir ('.vorda-install.' + [Guid]::NewGuid().ToString('N'))
$destination = Join-Path $binDir 'vorda.exe'
try {
    if (Test-Path -LiteralPath $destination) {
        $existing = Get-Item -LiteralPath $destination -Force
        if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Refusing to replace a linked or non-file destination.'
        }
    }
    [IO.File]::Copy($source.FullName, $staged, $false)
    $actual = (Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash
    if ($actual -ine $ExpectedSha256) {
        throw 'Artifact checksum mismatch; existing installation preserved.'
    }
    if ([IO.File]::Exists($destination)) {
        $backup = $staged + '.previous'
        [IO.File]::Replace($staged, $destination, $backup)
        [IO.File]::Delete($backup)
    } else {
        [IO.File]::Move($staged, $destination)
    }
    Write-Output "Installed $destination. Add $binDir to PATH if needed."
} finally {
    if ([IO.File]::Exists($staged)) { [IO.File]::Delete($staged) }
    $lock.Dispose()
}
