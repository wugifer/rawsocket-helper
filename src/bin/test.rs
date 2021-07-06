use pnet::packet::{ipv4::Ipv4Packet, tcp::TcpPacket};
use rand::thread_rng;
use rawsocket_helper::{
    out_going::{get_all, get_gw, get_iface_by_ip, get_ifaces, get_neighbour_mac, get_out_going_ip},
    recv::{recv_tcp, RecvPacket},
    send::{create_l2_channel, send_tcp},
    sys::is_root,
};
use std::net::Ipv4Addr;

fn test1() {
    println!("查询 root/管理员 权限");
    println!("is_root: {}", is_root());
    println!();
}

fn test2() {
    println!("查询网络接口");
    for (_, name, ipv4) in get_ifaces() {
        println!("{}, {}", name, ipv4);
    }
    println!();
}

fn test3() {
    println!("查询出网参数");
    let src_ip = get_out_going_ip().unwrap();
    let (src_if, src_if_name) = get_iface_by_ip(&src_ip.to_string()).unwrap();
    let dst_gw = get_gw(&src_if).unwrap();
    let (src_mac, dst_mac) = get_neighbour_mac(&src_if, &src_ip, &dst_gw).unwrap();

    println!("出网接口: {} {}", src_if.index, src_if_name);
    println!("本机地址: {:15} {}", src_ip, src_mac);
    println!("网关地址: {:15} {}", dst_gw, dst_mac);
    println!();
}

fn test4() {
    println!("测试发送 TCP 报文");
    let og = get_all().unwrap();
    let (mut tx, _) = create_l2_channel(&og.iface).unwrap();
    let mut rng = thread_rng();
    match send_tcp(
        &mut tx,
        0, // body 长度, 缺省填充为 0
        &og.src_mac,
        &og.dst_mac,
        &og.src_ip,
        &Ipv4Addr::new(8, 8, 8, 8),
        12345,
        53,
        &mut rng,
        |_x| false, // 修改生成的 TCP 报文, 如果修改 IP 头, 需同时修改校验和,
                    // 如果修改 TCP 部分, 返回 true 会自动更新校验和, _x 是从 l2 开始的数据
    ) {
        Ok(_) => {
            println!("发送 TCP 报文 ... 完成");
        }
        Err(err) => {
            println!("发送 TCP 报文 ... 失败 {}", err);
        }
    }
    println!();
}

fn test5() {
    println!("测试接收 TCP 报文");
    let og = get_all().unwrap();
    let (_, mut rx) = create_l2_channel(&og.iface).unwrap();
    match recv_tcp(&mut rx, None, 1, None, None, None, None, None, |packet, tcp_offset| {
        let ip_header = Ipv4Packet::new(&packet[14..]).unwrap();
        let tcp_header = TcpPacket::new(&packet[tcp_offset..]).unwrap();
        println!(
            "{}:{} -> {}:{}",
            ip_header.get_source(),
            tcp_header.get_source(),
            ip_header.get_destination(),
            tcp_header.get_destination()
        );
        RecvPacket::Count
    }) {
        Ok(_) => {
            println!("接收 TCP 报文 ... 完成");
        }
        Err(err) => {
            println!("接收 TCP 报文 ... 失败 {}", err);
        }
    }
    println!();
}

fn main() {
    test1();
    test2();
    test3();
    test4();
    test5();
}
