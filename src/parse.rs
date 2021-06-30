use cidr_utils::cidr::IpCidr;
use pnet::datalink::MacAddr;
use std::net::{IpAddr, Ipv4Addr};

/// 解析逗号分隔的 IP
///
/// ## 用法
///
/// ```
/// use rawsocket_helper::parse::parse_ips;
/// use std::net::Ipv4Addr;
///
/// assert_eq!(parse_ips(""), Vec::<Ipv4Addr>::new());
/// assert_eq!(
///     parse_ips("127.0.0.1,127.0.0.5"),
///     vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 5)]
/// );
/// ```
///
pub fn parse_ips(ips: &str) -> Vec<Ipv4Addr> {
    let mut parsed_ips = Vec::new();
    for range_ips in ips.split(',') {
        parsed_ips.append(&mut parse_range_ips(range_ips));
    }
    parsed_ips
}

/// 解析 MAC 地址
///
/// ## 用法
///
/// ```
/// use pnet::datalink::MacAddr;
/// use rawsocket_helper::parse::parse_mac;
///
/// assert_eq!(
///     parse_mac("11:22:33:44:55:aa"),
///     MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0xaa)
/// );
/// assert_eq!(
///     parse_mac("11:22:33:44:55:1z"),
///     MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x10)
/// );
/// assert_eq!(
///     parse_mac("11:22:33:44:55:678"),
///     MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x67)
/// );
/// assert_eq!(
///     parse_mac("11:22:33:44:55"),
///     MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
/// );
/// assert_eq!(
///     parse_mac("11:22:33:44:55:66:77"),
///     MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
/// );
/// ```
///
pub fn parse_mac(mac: &str) -> MacAddr {
    let arr: Vec<u32> = mac
        .split(':')
        .map(|x| {
            x.chars().fold(0, |s, y| {
                if s < 16 {
                    s * 16
                        + match y.to_digit(16) {
                            Some(n) => n,
                            None => 0,
                        }
                } else {
                    s
                }
            })
        })
        .collect();

    if arr.len() != 6 {
        return MacAddr::new(255, 255, 255, 255, 255, 255);
    }

    return MacAddr::new(
        arr[0] as u8,
        arr[1] as u8,
        arr[2] as u8,
        arr[3] as u8,
        arr[4] as u8,
        arr[5] as u8,
    );
}

/// 解析逗号分隔的端口
///
/// ## 用法
///
/// ```
/// use rawsocket_helper::parse::parse_ports;
///
/// assert_eq!(parse_ports(""), Vec::<u16>::new());
/// assert_eq!(parse_ports("5,8"), vec![5, 8]);
/// ```
///
pub fn parse_ports(ports: &str) -> Vec<u16> {
    //*

    let mut parsed_ports = Vec::new();
    for range_ports in ports.split(',') {
        parsed_ports.append(&mut parse_range_ports(range_ports));
    }
    parsed_ports
}

/// 解析单个 IP/IP 段
///
/// ## 用法
///
/// ```
/// use rawsocket_helper::parse::parse_range_ips;
/// use std::net::Ipv4Addr;
///
/// assert_eq!(parse_range_ips(""), Vec::<Ipv4Addr>::new());
/// assert_eq!(parse_range_ips("error"), Vec::<Ipv4Addr>::new());
/// assert_eq!(
///     parse_range_ips("127.0.0.1"),
///     vec![Ipv4Addr::new(127, 0, 0, 1)]
/// );
/// assert_eq!(
///     parse_range_ips("127.0.0.1/30"),
///     vec![
///         Ipv4Addr::new(127, 0, 0, 0),
///         Ipv4Addr::new(127, 0, 0, 1),
///         Ipv4Addr::new(127, 0, 0, 2),
///         Ipv4Addr::new(127, 0, 0, 3)
///     ]
/// );
/// ```
///
pub fn parse_range_ips(ip: &str) -> Vec<Ipv4Addr> {
    //*

    match IpCidr::from_str(&ip) {
        Ok(cidr) => cidr
            .iter()
            .filter_map(|x| match x {
                IpAddr::V4(addr) => Some(addr),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// 解析单个端口/区间
///
/// ## 用法
///
/// ```
/// use rawsocket_helper::parse::parse_range_ports;
///
/// assert_eq!(parse_range_ports(""), Vec::<u16>::new());
/// assert_eq!(parse_range_ports("error"), Vec::<u16>::new());
/// assert_eq!(parse_range_ports("65536"), Vec::<u16>::new());
/// assert_eq!(parse_range_ports("1-3"), vec![1, 2, 3]);
/// ```
///
pub fn parse_range_ports(range_ports: &str) -> Vec<u16> {
    //*

    let mut result: Vec<u16> = Vec::new();

    let ports = range_ports
        .split('-')
        .map(str::parse)
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if ports.is_err() {
        return result;
    }

    match ports.unwrap().as_slice() {
        [start] => {
            result.push(*start);
        }
        [start, end] => {
            result = ((*start)..(*end)).collect();
            // start .. end+1 在 end=65535 时溢出
            result.push(*end);
        }
        _ => {}
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_ips() {
        assert_eq!(parse_ips(""), Vec::<Ipv4Addr>::new());
        assert_eq!(parse_ips("127.0.0.1"), vec![Ipv4Addr::new(127, 0, 0, 1)]);
        assert_eq!(
            parse_ips("127.0.0.1,127.0.0.5"),
            vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(127, 0, 0, 5)]
        );
    }

    #[test]
    fn test_parse_mac() {
        assert_eq!(
            parse_mac("11:22:33:44:55:aa"),
            MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0xaa)
        );
        assert_eq!(
            parse_mac("11:22:33:44:55:1z"),
            MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x10)
        );
        assert_eq!(
            parse_mac("11:22:33:44:55:678"),
            MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x67)
        );
        assert_eq!(
            parse_mac("11:22:33:44:55"),
            MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
        );
        assert_eq!(
            parse_mac("11:22:33:44:55:66:77"),
            MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
        );
    }

    #[test]
    fn test_parse_ports() {
        assert_eq!(parse_ports(""), Vec::<u16>::new());
        assert_eq!(parse_ports("5"), vec![5]);
        assert_eq!(parse_ports("5,8"), vec![5, 8]);
    }

    #[test]
    fn test_parse_range_ips() {
        assert_eq!(parse_range_ips(""), Vec::<Ipv4Addr>::new());
        assert_eq!(parse_range_ips("error"), Vec::<Ipv4Addr>::new());
        assert_eq!(
            parse_range_ips("127.0.0.1"),
            vec![Ipv4Addr::new(127, 0, 0, 1)]
        );
        assert_eq!(
            parse_range_ips("127.0.0.1/30"),
            vec![
                Ipv4Addr::new(127, 0, 0, 0),
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 2),
                Ipv4Addr::new(127, 0, 0, 3)
            ]
        );
    }

    #[test]
    fn test_parse_range_ports() {
        assert_eq!(parse_range_ports(""), Vec::<u16>::new());
        assert_eq!(parse_range_ports("error"), Vec::<u16>::new());
        assert_eq!(parse_range_ports("65536"), Vec::<u16>::new());
        assert_eq!(parse_range_ports("1-3"), vec![1, 2, 3]);
        assert_eq!(parse_range_ports("65533-65535"), vec![65533, 65534, 65535]);
    }
}
