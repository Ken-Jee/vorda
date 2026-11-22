use super::error;
use crate::Result;
use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};
pub const MAX_FILE: u64 = 64_000_000;

pub fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.starts_with("~") {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| error("home directory is unavailable"))?;
        PathBuf::from(home).join(path.strip_prefix("~").map_err(error)?)
    } else {
        path.to_path_buf()
    };
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir().map_err(error)?.join(path)
    };
    refuse_links(&path)?;
    let mut normalized = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(c.as_os_str()),
        }
    }
    Ok(normalized)
}

pub fn linked(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                m.file_attributes() & 0x400 != 0
            }
            #[cfg(not(windows))]
            {
                m.file_type().is_symlink()
            }
        })
        .unwrap_or(false)
}

pub fn refuse_links(path: &Path) -> Result<()> {
    for p in path.ancestors() {
        if linked(p) {
            return Err(error("skipped path: symbolic link"));
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn open_regular(path: &Path, root: Option<&Path>, limit: u64) -> Result<File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
    };
    let path = absolute(path)?;
    let root = absolute(root.unwrap_or(Path::new("/")))?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| error("skipped path outside the selected folder"))?;
    if relative.as_os_str().is_empty() {
        return Err(error("skipped path: expected a regular file"));
    }
    let mut directory = File::open("/").map_err(error)?;
    let parts: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    for (i, component) in parts.iter().enumerate() {
        let component = CString::new(component.as_bytes()).map_err(error)?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if i + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            return Err(error(std::io::Error::last_os_error()));
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let info = directory.metadata().map_err(error)?;
    if !info.is_file() {
        return Err(error("skipped path: not a regular file"));
    }
    if info.nlink() > 1 {
        return Err(error("skipped path: hard-linked file"));
    }
    if info.len() > limit {
        return Err(error(format!("skipped path: larger than {limit} bytes")));
    }
    Ok(directory)
}

#[cfg(windows)]
pub fn open_regular(path: &Path, root: Option<&Path>, limit: u64) -> Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let path = absolute(path)?;
    if let Some(root) = root {
        if !path.starts_with(absolute(root)?) {
            return Err(error("skipped path outside the selected folder"));
        }
    }
    let mut ancestors = Vec::new();
    let mut parts: Vec<_> = path.ancestors().collect();
    parts.reverse();
    for p in parts {
        let file = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x02200000)
            .open(p)
            .map_err(error)?;
        if file.metadata().map_err(error)?.file_attributes() & 0x400 != 0 {
            return Err(error("skipped path: reparse point"));
        }
        ancestors.push(file);
    }
    let file = ancestors
        .pop()
        .ok_or_else(|| error("skipped path: expected a regular file"))?;
    let info = file.metadata().map_err(error)?;
    use std::os::windows::io::AsRawHandle;
    #[repr(C)]
    struct Information {
        attributes: u32,
        created: [u32; 2],
        accessed: [u32; 2],
        written: [u32; 2],
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut Information)
            -> i32;
    }
    let mut by_handle = std::mem::MaybeUninit::<Information>::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), by_handle.as_mut_ptr()) } == 0 {
        return Err(error(std::io::Error::last_os_error()));
    }
    let by_handle = unsafe { by_handle.assume_init() };
    if !info.is_file() || by_handle.links > 1 {
        return Err(error("skipped path: not an unlinked regular file"));
    }
    if info.len() > limit {
        return Err(error("skipped path: larger than limit"));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub fn open_regular(_: &Path, _: Option<&Path>, _: u64) -> Result<File> {
    Err(error("safe file reads are unavailable on this platform"))
}

pub fn read_regular(path: &Path, root: Option<&Path>, limit: u64, prefix: bool) -> Result<Vec<u8>> {
    let file = open_regular(path, root, if prefix { u64::MAX } else { limit })?;
    let mut data = Vec::new();
    file.take(limit.saturating_add(u64::from(!prefix)))
        .read_to_end(&mut data)
        .map_err(error)?;
    if data.len() as u64 > limit {
        return Err(error(format!("skipped path: larger than {limit} bytes")));
    }
    Ok(data)
}
pub fn text(path: &Path) -> Result<String> {
    String::from_utf8(read_regular(path, None, MAX_FILE, false)?).map_err(error)
}
