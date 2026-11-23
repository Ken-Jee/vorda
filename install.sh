#!/bin/sh
# Install Vorda on Linux (x86_64 or arm64):
#   curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh
# Downloads the Linux release for your CPU, checks its SHA-256 checksum, and
# puts vorda in ~/.local/bin (set VORDA_INSTALL_DIR to pick another folder, or
# VORDA_VERSION=0.2.0 to install a specific version). Adds that folder to your
# PATH once unless VORDA_NO_MODIFY_PATH=1 is set.
# VORDA_INSTALL_FROM=DIR installs offline from a local folder with SHA256SUMS
# and release executables, checking the checksum without curl or wget.
# When minisign is on PATH, requires and verifies SHA256SUMS.minisig and the
# binary .minisig with the Vorda release key, exiting without installing if
# missing or invalid; otherwise checks SHA-256 only. Saves vorda.minisig beside
# the binary when present.
# Everything runs inside main, so a cut-off download runs nothing.
set -eu

repo=Ken-Jee/vorda
docs=https://github.com/$repo/blob/main/docs/install.md
# Vorda release public key (rust/release/vorda-release.pub, key ID 57E5204A70E3811B).
release_key=RWQbgeNwSiDlVx1es199wQE3gUxSQV2A91DIV+24xn3O8WTVFxZUh0qG # gitleaks:allow (public key)

fail() {
  echo "vorda install: $*" >&2
  exit 1
}

# Pick the release build for this OS and CPU.
detect_target() {
  os=$(uname -s)
  cpu=$(uname -m)
  case $os in
    Linux)
      case $cpu in
        x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
        aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
        *) fail "no download is available for $os $cpu yet (only Linux x86_64 and arm64 downloads exist today); you can build from source at $docs" ;;
      esac
      ;;
    *) fail "no download is available for $os yet (Linux is the only download today; macOS and Windows are coming); you can build from source at $docs" ;;
  esac
}

# Add dir to PATH in the shell profile, once.
add_to_path() {
  case ${SHELL:-} in
    */fish)
      echo "Add $dir to your PATH in fish so you can run vorda: fish_add_path $dir"
      return
      ;;
    */zsh) profile=$HOME/.zshrc ;;
    */bash) profile=$HOME/.bashrc ;;
    *) profile=$HOME/.profile ;;
  esac
  line="export PATH=\"$dir:\$PATH\""
  if [ -f "$profile" ] && grep -qxF "$line" "$profile"; then
    return
  fi
  printf '\n# Added by the Vorda installer\n%s\n' "$line" >> "$profile"
  echo "Added $dir to your PATH in $profile. Open a new terminal window so you can run vorda."
}

main() {
  dir=${VORDA_INSTALL_DIR:-$HOME/.local/bin}
  detect_target

  if [ -n "${VORDA_INSTALL_FROM:-}" ]; then
    base=$VORDA_INSTALL_FROM
  elif [ -n "${VORDA_VERSION:-}" ]; then
    base=https://github.com/$repo/releases/download/v${VORDA_VERSION#v}
  else
    base=https://github.com/$repo/releases/latest/download
  fi

  if [ -n "${VORDA_INSTALL_FROM:-}" ]; then
    fetch() { cp "$1" "$2"; }
  elif command -v curl > /dev/null 2>&1; then
    fetch() { curl --proto '=https' --tlsv1.2 -fsSL -o "$2" "$1"; }
  elif command -v wget > /dev/null 2>&1; then
    # BusyBox wget has no --https-only; every URL here is https already.
    if wget --help 2>&1 | grep -q -- --https-only; then
      fetch() { wget -q --https-only -O "$2" "$1"; }
    else
      fetch() { wget -q -O "$2" "$1"; }
    fi
  else
    fail "please install curl or wget first, then run this installer again"
  fi
  if command -v sha256sum > /dev/null 2>&1; then
    digest() { sha256sum "$1" | cut -d ' ' -f 1; }
  elif command -v shasum > /dev/null 2>&1; then
    digest() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
  else
    fail "could not find sha256sum or shasum to check the download"
  fi

  signed=
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 1' INT TERM

  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download checksums from $base/SHA256SUMS"
  # With minisign on PATH, SHA256SUMS must carry a valid release signature.
  if command -v minisign > /dev/null 2>&1; then
    fetch "$base/SHA256SUMS.minisig" "$tmp/SHA256SUMS.minisig" || fail "could not download SHA256SUMS.minisig from $base; nothing was installed. Releases v0.1.0 and v0.1.1 are unsigned."
    minisign -V -q -P "$release_key" -m "$tmp/SHA256SUMS" -x "$tmp/SHA256SUMS.minisig" > /dev/null 2>&1 || fail "SHA256SUMS.minisig failed signature verification; nothing was installed."
    signed=1
  fi
  line=$(grep -E "^[0-9a-f]{64}  vorda-[0-9A-Za-z.+-]+-$target\$" "$tmp/SHA256SUMS" | head -n 1) || true
  [ -n "$line" ] || fail "this release has no download for $target in SHA256SUMS"
  expected=${line%% *}
  name=${line#*  }

  fetch "$base/$name" "$tmp/vorda" || fail "could not download $base/$name"
  actual=$(digest "$tmp/vorda")
  [ "$actual" = "$expected" ] || fail "checksum check failed for $name (expected $expected, got $actual); nothing was installed"
  # The executable's own signature lets vorda verify-self check this copy later.
  if [ -n "$signed" ]; then
    fetch "$base/$name.minisig" "$tmp/vorda.minisig" || fail "could not download $name.minisig from $base; nothing was installed."
    minisign -V -q -P "$release_key" -m "$tmp/vorda" -x "$tmp/vorda.minisig" > /dev/null 2>&1 || fail "$name.minisig failed signature verification; nothing was installed."
  else
    # Best effort; an empty file (wget on error, empty response) is not a signature.
    if ! fetch "$base/$name.minisig" "$tmp/vorda.minisig" 2> /dev/null || [ ! -s "$tmp/vorda.minisig" ]; then
      rm -f "$tmp/vorda.minisig"
    fi
  fi

  mkdir -p "$dir"
  chmod 755 "$tmp/vorda"
  if [ -f "$tmp/vorda.minisig" ]; then
    mv -f "$tmp/vorda.minisig" "$dir/vorda.minisig"
  else
    rm -f "$dir/vorda.minisig"
  fi
  mv -f "$tmp/vorda" "$dir/vorda"
  echo "Installed vorda ($name) to $dir/vorda."
  if [ -n "$signed" ]; then
    echo "Verified SHA256SUMS and executable signatures (Vorda release key 57E5204A70E3811B) and SHA-256 checksum."
  else
    echo "Verified SHA-256 checksum only (minisign not found on PATH; install minisign to also check the release signature)."
  fi
  case ":$PATH:" in
    *":$dir:"*) ;;
    *)
      if [ -n "${VORDA_NO_MODIFY_PATH:-}" ]; then
        echo "Add $dir to your PATH to run vorda, for example: export PATH=\"$dir:\$PATH\""
      else
        add_to_path
      fi
      ;;
  esac
  echo "Next: run vorda setup to choose offline or online advisories and scan this machine."
}

main "$@"
