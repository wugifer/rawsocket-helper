use python_comm::prelude::raise_error;
use python_comm_macros::auto_func_name2;
use std::{io, ptr};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::winnt::{TokenElevation, HANDLE, TOKEN_ELEVATION, TOKEN_QUERY};

/// 判断 root 权限
pub fn is_root() -> bool {
    //*

    _is_root().unwrap_or(false)
}

/// 判断 root 权限
#[auto_func_name2]
fn _is_root() -> Result<bool, anyhow::Error> {
    //*

    unsafe {
        // 获取令牌句柄
        let mut handle: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) == 0 {
            return raise_error!(__func__, "\n", io::Error::last_os_error());
        }

        // 获取令牌信息, 用于判断 root 权限
        let mut elevation = TOKEN_ELEVATION::default();
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut ret_size = size;
        if GetTokenInformation(
            handle,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut ret_size,
        ) == 0
        {
            CloseHandle(handle);
            return raise_error!(__func__, "\n", io::Error::last_os_error());
        }

        CloseHandle(handle);
        return Ok(elevation.TokenIsElevated != 0);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_root() {
        // assert_eq!(_is_root().unwrap(), true);
        let _ = is_root();
    }
}
