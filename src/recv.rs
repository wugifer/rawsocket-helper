//! 使用 pnet 通道接收数据
//!
//! ## l2 用法
//!
//! ```
//! use rawsocket_helper::{
//!     out_going::{
//!         get_all,
//!     },
//!     recv::{RecvPacket, create_l2_channel, recv_tcp},
//! };
//! use pnet::packet::{
//!     ipv4::Ipv4Packet,
//!     tcp::TcpPacket,
//! };
//!
//! let og = get_all().unwrap();
//! let (_, mut rx) = create_l2_channel(&og.iface).unwrap();
//! recv_tcp(&mut rx, None, 1, None, None, None, None, None, |packet, tcp_offset| {
//!     let ip_header = Ipv4Packet::new(&packet[14..]).unwrap();
//!     let tcp_header = TcpPacket::new(&packet[tcp_offset..]).unwrap();
//!     println!(
//!         "{}:{} -> {}:{}",
//!         ip_header.get_source(),
//!         tcp_header.get_source(),
//!         ip_header.get_destination(),
//!         tcp_header.get_destination()
//!     );
//!     RecvPacket::Count
//! }).unwrap();
//! ```
//!

use pnet::{
    datalink::DataLinkReceiver,
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
    },
};
use python_comm::prelude::raise_error;
use python_comm_macros::auto_func_name2;
use std::{
    net::Ipv4Addr,
    sync::mpsc::Receiver,
    time::{Duration, Instant},
};

pub use crate::send::create_l2_channel;

/// recv_tcp handle_func 返回值
pub enum RecvPacket {
    /// 计数
    Count,
    /// 不计数
    Discard,
    /// 立即终止
    Exit,
}

/// recv_tcp 封装
struct RecvTcp<F>
where
    F: FnMut(&[u8], usize) -> RecvPacket,
{
    msg: Option<Receiver<String>>, // 接收消息
    count: u64,                    // 最大处理总数
    timeout: Option<Duration>,     // 超时时间
    src_ip: Option<Ipv4Addr>,      // 匹配源 IP
    dst_ip: Option<Ipv4Addr>,      // 匹配目的 IP
    src_port: Option<u16>,         // 匹配源端口
    dst_port: Option<u16>,         // 匹配目的端口
    handle_func: F,                // 满足匹配条件后的进一步处理
}

impl<F> RecvTcp<F>
where
    F: FnMut(&[u8], usize) -> RecvPacket,
{
    /// recv_tcp 的类封装
    #[auto_func_name2]
    fn __call__(&mut self, rx: &mut Box<dyn DataLinkReceiver>) -> Result<u64, anyhow::Error> {
        let mut count: u64 = 0;
        let start = Instant::now();
        loop {
            // 极端情况下没有任何报文, 这里会阻塞
            if let Ok(packet) = rx.next() {
                if let Some(frame) = EthernetPacket::new(packet) {
                    if frame.get_ethertype() == EtherTypes::Ipv4 {
                        match self.recv_ipv4(packet) {
                            RecvPacket::Count => {
                                count += 1;
                            }
                            RecvPacket::Discard => {}
                            RecvPacket::Exit => {
                                return Ok(count);
                            }
                        }
                    }
                }
            }

            // 处理消息
            if self.msg.is_some() && self.handle_msg_and_exit() {
                return Ok(count);
            }

            // 数量满足
            if self.count > 0 && count >= self.count {
                return Ok(count);
            }

            // 或者超时
            if self.timeout.is_some() && self.timeout.unwrap() < Instant::now().duration_since(start) {
                return Err(raise_error!(__func__, "超时"));
            }
        }
    }

    /// 处理消息, 当需要立即终止时返回 true
    fn handle_msg_and_exit(&self) -> bool {
        match &self.msg {
            Some(msg) => match msg.try_recv() {
                Ok(text) => text == "stop",
                Err(_) => false,
            },
            None => false,
        }
    }

    /// 构造
    fn new(
        msg: Option<Receiver<String>>,
        count: u64,
        timeout: Option<Duration>,
        src_ip: Option<Ipv4Addr>,
        dst_ip: Option<Ipv4Addr>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        handle_func: F,
    ) -> Self {
        Self {
            msg,
            count,
            timeout,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            handle_func,
        }
    }

    /// 接收 ipv4 报文
    fn recv_ipv4(&mut self, packet: &[u8]) -> RecvPacket {
        if packet.len() <= 14 {
            return RecvPacket::Discard;
        }

        // L3
        if let Some(ip_header) = Ipv4Packet::new(&packet[14..]) {
            let length: usize = ((ip_header.get_header_length() & 0x0F) << 2) as usize;

            if ip_header.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {}
            if self.src_ip.is_some() && self.src_ip.unwrap() != ip_header.get_source() {}
            if self.dst_ip.is_some() && self.dst_ip.unwrap() != ip_header.get_destination() {}

            return self.recv_tcp(packet, 14 + length);
        }

        RecvPacket::Discard
    }

    /// 接收 tcp 报文
    fn recv_tcp(&mut self, packet: &[u8], tcp_offset: usize) -> RecvPacket {
        if packet.len() <= tcp_offset {
            return RecvPacket::Discard;
        }

        if let Some(tcp_header) = TcpPacket::new(&packet[tcp_offset..]) {
            if self.src_port.is_some() && self.src_port != Some(tcp_header.get_source()) {
                return RecvPacket::Discard;
            }
            if self.dst_port.is_some() && self.dst_port != Some(tcp_header.get_destination()) {
                return RecvPacket::Discard;
            }

            return (self.handle_func)(packet, tcp_offset);
        }

        RecvPacket::Discard
    }
}

/// 通过 pnet L2 通道接收 tcp 报文
///
/// 报文特征符合 src_ip, dst_ip, src_port, dst_port 要求的, 送给 handle_func 处理
///
/// handle_func 返回 COUNT 的进行计数
/// handle_func 返回 DISCARD 的不进行任何处理
/// handle_func 返回 EXIT 的终止接收
///
/// 当计数达到 count(非零) 或持续时间达到 timeout 时终止接收
///
#[auto_func_name2]
pub fn recv_tcp<F>(
    rx: &mut Box<dyn DataLinkReceiver>,
    msg: Option<Receiver<String>>,
    count: u64,
    timeout: Option<Duration>,
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    handle_func: F,
) -> Result<u64, anyhow::Error>
where
    F: FnMut(&[u8], usize) -> RecvPacket,
{
    RecvTcp::new(msg, count, timeout, src_ip, dst_ip, src_port, dst_port, handle_func).__call__(rx)
}
