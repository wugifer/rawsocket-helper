use sudo::RunningAs;

/// 判断 root 权限
pub fn is_root() -> bool {
    //*

    match sudo::check() {
        RunningAs::Root => true,
        RunningAs::User => false,
        RunningAs::Suid => true,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_is_root() {
        // assert_eq!(is_root(), true);
        let _ = is_root();
    }
}
