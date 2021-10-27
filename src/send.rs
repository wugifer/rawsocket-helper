//!
//! 使用 pnet 通道发送数据
//!
//! ## l2 用法
//!
//! ```
//! use rand::thread_rng;
//! use rawsocket_helper::{
//!     out_going::{
//!         get_all,
//!     },
//!     send::{create_l2_channel, send_tcp},
//! };
//! use std::net::Ipv4Addr;
//!
//! let og = get_all().unwrap();
//! let (mut tx, _) = create_l2_channel(&og.iface).unwrap();
//! let mut rng = thread_rng();
//! send_tcp(
//!     &mut tx,
//!     0, // body 长度, 缺省填充为 0
//!     &og.src_mac,
//!     &og.dst_mac,
//!     &og.src_ip,
//!     &Ipv4Addr::new(8, 8, 8, 8),
//!     1234,
//!     53,
//!     &mut rng,
//!     |_x| false, // 修改生成的 TCP 报文, 如果修改 IP 头, 需同时修改校验和,
//!                 // 如果修改 TCP 部分, 返回 true 会自动更新校验和, _x 是从 l2 开始的数据
//! ).unwrap();
//! ```
//!

use pnet::{
    datalink::{channel, Channel, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{checksum as ipv4_checksum, Ipv4Flags, MutableIpv4Packet},
        tcp::{ipv4_checksum as tcp_checksum, MutableTcpPacket, TcpFlags},
    },
    transport::{transport_channel, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender},
};
use python_comm::raise_error_use::*;
use rand::{rngs::ThreadRng, Rng};
use std::net::Ipv4Addr;

/// 构造 L2 + L3 + L4 TCP 包
pub fn build_l2_tcp_packet(
    tx_packet: &mut [u8],
    body_size: usize,
    src_mac: &MacAddr,
    dst_mac: &MacAddr,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut ThreadRng,
) {
    // L2
    if let Some(mut eth_header) = MutableEthernetPacket::new(&mut tx_packet[..14]) {
        eth_header.set_destination(*dst_mac);
        eth_header.set_source(*src_mac);
        eth_header.set_ethertype(EtherTypes::Ipv4);
    }

    // L3
    if let Some(mut ip_header) = MutableIpv4Packet::new(&mut tx_packet[14..(14 + 20)]) {
        ip_header.set_header_length(69);
        ip_header.set_total_length(40 + body_size as u16);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(*src_ip);
        ip_header.set_destination(*dst_ip);
        ip_header.set_identification(rng.gen::<u16>());
        ip_header.set_ttl(64);
        ip_header.set_version(4);
        ip_header.set_flags(Ipv4Flags::DontFragment);

        let checksum = ipv4_checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // L4
    if let Some(mut tcp_header) = MutableTcpPacket::new(&mut tx_packet[(14 + 20)..]) {
        build_l4_tcp_packet(&mut tcp_header, src_ip, dst_ip, src_port, dst_port, rng);
    }
}

/// 构造 L4 TCP 包
pub fn build_l4_tcp_packet(
    tx_packet: &mut MutableTcpPacket,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut ThreadRng,
) {
    tx_packet.set_source(src_port);
    tx_packet.set_destination(dst_port);
    tx_packet.set_sequence(rng.gen::<u32>());
    tx_packet.set_acknowledgement(0);
    tx_packet.set_flags(TcpFlags::SYN);
    tx_packet.set_window(30000 + (rng.gen::<u8>() as u16 * 17));
    tx_packet.set_data_offset(5);
    tx_packet.set_urgent_ptr(0);

    let checksum = tcp_checksum(&tx_packet.to_immutable(), src_ip, dst_ip);
    tx_packet.set_checksum(checksum);
}

/// 创建 pnet L2 通道
///
/// tip: 在 Windows 平台, 如果 WinPcap (Npcap 兼容模式) 未正确安装, 无法收到包, 并且不报错!
#[auto_func_name]
pub fn create_l2_channel(
    iface: &NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), anyhow::Error> {
    match channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => raise_error!(__func__, "不支持的通道类型"),
        Err(err) => raise_error!(__func__, "\n", err),
    }
}

/// 创建 pnet L4 通道
#[auto_func_name]
pub fn create_l4_channel() -> Result<(TransportSender, TransportReceiver), anyhow::Error> {
    let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    transport_channel(256, protocol).or_else(|err| {
        let text = format!("{:?}", err);
        if text.contains("code: 10013,") {
            raise_error!(__func__, "权限不足")
        } else {
            raise_error!(__func__, "\n", err)
        }
    })
}

/// 通过 pnet L2 通道构造并发送 tcp 报文
#[auto_func_name]
pub fn send_tcp<F>(
    tx: &mut Box<dyn DataLinkSender>,
    body_size: usize,
    src_mac: &MacAddr,
    dst_mac: &MacAddr,
    src_ip: &Ipv4Addr,
    dst_ip: &Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut ThreadRng,
    modify_packet_func: F,
) -> Result<(), anyhow::Error>
where
    F: Fn(&mut [u8]) -> bool,
{
    // Step2. 发送
    if let None = tx.build_and_send(1, 14 + 20 + 20 + body_size, &mut |tx_packet: &mut [u8]| {
        // Step0. 构造 TCP 报文
        build_l2_tcp_packet(
            tx_packet, body_size, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, rng,
        );
        // Step1. 修改构造好的 TCP 报文, 计算校验和
        if modify_packet_func(tx_packet) {
            set_l2_tcp_packet_checksum(tx_packet, src_ip, dst_ip);
        }
    }) {
        return raise_error!(__func__, "创建或发送失败");
    }

    Ok(())
}

/// 计算 TCP 校验和
fn set_l2_tcp_packet_checksum(tx_packet: &mut [u8], src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr) {
    if let Some(mut tcp_header) = MutableTcpPacket::new(&mut tx_packet[(14 + 20)..]) {
        tcp_header.set_checksum(0);
        let checksum = tcp_checksum(&tcp_header.to_immutable(), src_ip, dst_ip);
        tcp_header.set_checksum(checksum);
    }
}
