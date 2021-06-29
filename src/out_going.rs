use byteorder::{BigEndian, ReadBytesExt};
use ipnetwork::IpNetwork;
use pnet::{
    datalink::{channel, interfaces, Channel, DataLinkReceiver, MacAddr, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        icmp::{IcmpPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        MutablePacket, Packet,
    },
};
use python_comm::raise_error;
use python_comm_macros::auto_func_name2;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    time::{Duration, Instant},
};

#[cfg(not(windows))]
use pnet::datalink::{ChannelType, Config};

/// 访问外网使用的信息
pub struct OutGoing {
    /// 访问外网使用的接口, pnet::datalink::interfaces() 序号
    pub if_index: u32,

    /// 访问外网使用的接口, 名称
    pub if_name: String,

    /// 访问外网使用的源 MAC, if_index/src_ip 对应的 MAC
    pub src_mac: MacAddr,

    /// 访问外网使用的目的 MAC, dst_gw 对应的 MAC
    pub dst_mac: MacAddr,

    /// 访问外网使用的源 IP, if_index 对应的 IP
    pub src_ip: Ipv4Addr,

    /// 访问外网使用的网关 IP
    pub dst_gw: Ipv4Addr,
}

/// 创建 ARP 报文
#[auto_func_name2]
fn create_arp_packet(
    packet: &mut MutableArpPacket,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Result<(), anyhow::Error> {
    //*

    packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    packet.set_protocol_type(EtherTypes::Ipv4);
    packet.set_hw_addr_len(6);
    packet.set_proto_addr_len(4);
    packet.set_operation(ArpOperations::Request);
    packet.set_sender_hw_addr(src_mac);
    packet.set_sender_proto_addr(src_ip);
    packet.set_target_hw_addr(MacAddr::zero());
    packet.set_target_proto_addr(dst_ip);

    Ok(())
}

/// 创建用于 ARP 的 ETHER 报文
#[auto_func_name2]
fn create_ether_arp_packet(
    packet: &mut MutableEthernetPacket,
    src_mac: MacAddr,
    mut arp_packet: MutableArpPacket,
) -> Result<(), anyhow::Error> {
    //*

    packet.set_destination(MacAddr::broadcast());
    packet.set_source(src_mac);
    packet.set_ethertype(EtherTypes::Arp);
    packet.set_payload(arp_packet.packet_mut());

    Ok(())
}

/// 获取访问外网的数据
pub fn get_all() -> Option<OutGoing> {
    //*

    if let Ok(src_ip) = get_out_going_ip() {
        if let Some((if_index, if_name)) = get_iface_by_ip(&src_ip.to_string()) {
            if let Ok(dst_gw) = get_gw(if_index) {
                if let Ok((src_mac, dst_mac)) = get_neighbour_mac(if_index, &src_ip, &dst_gw) {
                    return Some(OutGoing {
                        if_index,
                        if_name,
                        src_mac,
                        dst_mac,
                        src_ip,
                        dst_gw,
                    });
                }
            }
        }
    }

    None
}

/// 获取访问外网使用的网关 IP
///
/// 见 get_out_going_ip
///
#[cfg(not(windows))]
#[auto_func_name2]
pub fn get_gw(if_index: u32) -> Result<Ipv4Addr, anyhow::Error> {
    //*

    // 发送 trick 报文
    let _ = send_trick_packet();

    // 接收 trick 报文触发的 ICMP 报文
    let iface = get_iface(if_index)
        .ok_or_else(|| raise_error!(__func__, format!("无法获得指定的接口 {}", if_index)))?;
    let (mut _tx, mut rx) = match channel(
        &iface,
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: None,
            write_timeout: None,
            channel_type: ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
        },
    ) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => Err(raise_error!(__func__, "不支持的通道类型"))?,
        Err(err) => raise_error!(__func__, "\n", err)?,
    };
    recv_trick_packet(&mut rx, Duration::from_millis(3000))
}

/// 获取访问外网使用的网关 IP
///
/// 见 get_out_going_ip
///
#[cfg(target_os = "windows")]
#[auto_func_name2]
pub fn get_gw(if_index: u32) -> Result<Ipv4Addr, anyhow::Error> {
    //*

    // 发送 trick 报文
    let _ = send_trick_packet();

    // 接收 trick 报文触发的 ICMP 报文
    let iface = get_iface(if_index)
        .ok_or_else(|| raise_error!(__func__, format!("无法获得指定的接口 {}", if_index)))?;
    let (mut _tx, mut rx) = match channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => Err(raise_error!(__func__, "不支持的通道类型"))?,
        Err(err) => raise_error!(__func__, "\n", err)?,
    };
    recv_trick_packet(&mut rx, Duration::from_millis(3000))
}

/// 获取指定网卡
pub fn get_iface(if_index: u32) -> Option<NetworkInterface> {
    //*

    interfaces()
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.index == if_index)
        .next()
}

/// 获取访问外网使用的本地网卡
///
/// 见 get_out_going_ip
///
pub fn get_iface_by_ip(out_going_ip: &String) -> Option<(u32, String)> {
    //*

    for iface in interfaces() {
        for ip in iface.ips {
            if ip.ip().to_string() == *out_going_ip {
                return Some((iface.index, iface.name));
            }
        }
    }

    return None;
}

/// 获取所有网卡, 包含名字、IPv4 地址/掩码列表
///
/// 用法
///
/// ```
/// use rawsocket_helper::out_going::*;
///
/// for (name, ips_v4) in get_ifaces() {
///   println!("{}, {}", name, ips_v4);
/// }
/// ```
///
pub fn get_ifaces() -> Vec<(String, String)> {
    //*

    interfaces()
        .into_iter()
        .map(|iface| {
            let ips: Vec<String> = iface
                .ips
                .into_iter()
                .filter_map(|ip| match ip {
                    IpNetwork::V4(ipv4) => Some(format!("{}/{}", ipv4.ip(), ipv4.prefix())),
                    _ => None,
                })
                .collect();
            (iface.name, format!("{:?}", ips))
        })
        .collect()
}

/// 获取自身的 MAC 地址以及同网段 IP 的 MAC 地址
///
/// 见 get_out_going_ip
///
#[auto_func_name2]
pub fn get_neighbour_mac(
    if_index: u32,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
) -> Result<(MacAddr, MacAddr), anyhow::Error> {
    //*

    // 建立收发报文通道
    let iface = get_iface(if_index)
        .ok_or_else(|| raise_error!(__func__, format!("无法获得指定的接口 {}", if_index)))?;
    let src_mac = iface
        .mac
        .ok_or_else(|| raise_error!(__func__, "无法获得接口 MAC 地址"))?;
    let (mut tx, mut rx) = match channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => Err(raise_error!(__func__, "不支持的通道类型"))?,
        Err(err) => raise_error!(__func__, "\n", err)?,
    };

    // arp
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
        .ok_or_else(|| raise_error!(__func__, "无法创建 ARP 报文"))?;
    create_arp_packet(&mut arp_packet, src_mac, src_ip.clone(), dst_ip.clone())
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    // ether
    let mut ether_buffer = [0u8; 42];
    let mut ether_packet = MutableEthernetPacket::new(&mut ether_buffer)
        .ok_or_else(|| raise_error!(__func__, "无法创建 ETHER 报文"))?;
    create_ether_arp_packet(&mut ether_packet, src_mac, arp_packet)
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    // 发送
    tx.send_to(ether_packet.packet(), None)
        .ok_or_else(|| raise_error!(__func__, "发送失败"))?
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    let start_time = Instant::now();
    let timeout = Duration::from_millis(500);
    loop {
        // 反复尝试, 直到从一个正确的报文中提取到 MAC 地址
        if let Ok(frame) = rx.next() {
            if let Some(frame) = EthernetPacket::new(frame) {
                if frame.get_ethertype() == EtherTypes::Arp {
                    if let Some(dst_mac) = recv_arp(&frame, dst_ip.clone()) {
                        return Ok((src_mac, dst_mac));
                    }
                }
            }
        }

        // 或者超时
        if Instant::now().duration_since(start_time) > timeout {
            return Err(raise_error!(
                __func__,
                format!("无法获得 {} 的 MAC 地址", dst_ip)
            ));
        }
    }
}

/// 获取访问外网使用的本地 IP
///
/// ## 用法
///
/// ```
/// use rawsocket_helper::out_going::*;
///
/// let out_going_ip = get_out_going_ip().unwrap();
/// let (out_going_if, out_going_if_name) = get_iface_by_ip(&out_going_ip.to_string()).unwrap();
/// let out_going_gw = get_gw(out_going_if).unwrap();
/// let (out_going_src_mac, out_going_dst_mac) =
///     get_neighbour_mac(out_going_if, &out_going_ip, &out_going_gw).unwrap();
/// println!("out_going_if: {} {}", out_going_if, out_going_if_name);
/// println!("out_going_ip: {}", out_going_ip);
/// println!("out_going_gw: {}", out_going_gw);
/// println!("out_going_src_mac: {}", out_going_src_mac);
/// println!("out_going_dst_mac: {}", out_going_dst_mac);
/// ```
///
#[auto_func_name2]
pub fn get_out_going_ip() -> Result<Ipv4Addr, anyhow::Error> {
    //*

    let socket = UdpSocket::bind("0.0.0.0:0").or_else(|err| raise_error!(__func__, "\n", err))?;

    // 并不需要 8.8.8.8 能真实连通
    socket
        .connect("8.8.8.8:80")
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    match socket.local_addr() {
        Ok(addr) => match addr.ip() {
            IpAddr::V4(ip) => Ok(ip),
            _ => Err(raise_error!(__func__, "不支持 IPv6")),
        },
        Err(err) => raise_error!(__func__, "\n", err),
    }
}

/// ARP 报文处理, 从 ARP 报文提取 MAC 地址
fn recv_arp(ethernet: &EthernetPacket, dst_ip: Ipv4Addr) -> Option<MacAddr> {
    //*

    if let Some(packet) = ArpPacket::new(ethernet.payload()) {
        if packet.get_sender_proto_addr() == dst_ip {
            return Some(packet.get_sender_hw_addr());
        }
    }

    None
}

/// trick 报文处理, 从 ICMP 报文提取 IP 地址
fn recv_trick_icmp(ip_packet: &Ipv4Packet) -> Option<Ipv4Addr> {
    //*

    if let Some(packet) = IcmpPacket::new(ip_packet.payload()) {
        if packet.get_icmp_type() == IcmpTypes::TimeExceeded {
            let payload = packet.payload();
            let mut cursor = Cursor::new(payload);
            cursor.set_position(20);
            if let Ok(dst_ip) = cursor.read_u32::<BigEndian>() {
                if dst_ip == 0x08080808 {
                    return Some(ip_packet.get_source());
                }
            }
        }
    }

    None
}

/// trick 报文处理, 从 IP 报文提取 IP 地址
fn recv_trick_ipv4(ethernet: &EthernetPacket) -> Option<Ipv4Addr> {
    //*

    if let Some(packet) = Ipv4Packet::new(ethernet.payload()) {
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
            return recv_trick_icmp(&packet);
        }
    }

    None
}

/// 接收 trick 报文触发的 ICMP 报文
#[auto_func_name2]
fn recv_trick_packet(
    rx: &mut Box<dyn DataLinkReceiver>,
    timeout: Duration,
) -> Result<Ipv4Addr, anyhow::Error> {
    //*

    let start_time = Instant::now();
    loop {
        // 反复尝试, 直到从一个正确的报文中提取到 IP 地址
        if let Ok(frame) = rx.next() {
            if let Some(frame) = EthernetPacket::new(frame) {
                if frame.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip_addr) = recv_trick_ipv4(&frame) {
                        return Ok(ip_addr);
                    }
                }
            }
        }

        // 或者超时
        if Instant::now().duration_since(start_time) > timeout {
            return Err(raise_error!(__func__, "超时"));
        }

        // 重新发送 trick 报文, 增加收到的可能性
        let _ = send_trick_packet();
    }
}

/// 发送访问外网的 trick 报文
#[auto_func_name2]
fn send_trick_packet() -> Result<(), anyhow::Error> {
    //*

    let socket = UdpSocket::bind("0.0.0.0:0").or_else(|err| raise_error!(__func__, "\n", err))?;
    socket
        .set_ttl(1)
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    let buf = [0u8; 0];
    let dest: &str = "8.8.8.8:80";
    socket
        .send_to(&buf, dest)
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    Ok(())
}
