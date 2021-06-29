mod info;

#[cfg(unix)]
#[path = "linux.rs"]
mod sys;

#[cfg(windows)]
#[path = "windows.rs"]
mod sys;

pub mod prelude;
