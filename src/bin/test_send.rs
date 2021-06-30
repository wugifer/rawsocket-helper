use pnet::{datalink::NetworkInterface, packet::tcp::MutableTcpPacket};
use python_comm::prelude::raise_error;
use python_comm_macros::auto_func_name2;
use rand::{rngs::ThreadRng, thread_rng, Rng};
use rawsocket_helper::{
    out_going::{get_iface_by_name, get_ifaces},
    parse::parse_mac,
    send::{build_l4_tcp_packet, create_l2_channel, create_l4_channel, send_tcp},
};
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
};

/// 入口
fn main() {
    //*

    if let Err(err) = main_error() {
        println!("{}", err)
    }
}

/// 含错误信息的入口
#[auto_func_name2]
fn main_error() -> Result<(), anyhow::Error> {
    //*

    println!("命令: {}", env::args().collect::<Vec<String>>().join(" "));

    // 程序名, 用法
    let app_name = env::args().nth(0).unwrap_or(String::from("app"));
    let usage = format!(
        "{}\n{}\n{}",
        "用法:",
        format!(
            "    {} iface_name gateway_mac - 测试不同的发送方案",
            app_name
        ),
        format!("    {} list - 列出接口名称及 IP", app_name)
    );

    // 检查接口名称
    let if_name = env::args()
        .nth(1)
        .ok_or_else(|| raise_error!(__func__, format!("缺少命令行参数:\n{}", usage.clone())))?;

    // 列表
    if if_name == "list" {
        for (_iface, if_name, ipv4s) in get_ifaces() {
            println!("{} {}", if_name, ipv4s);
        }
        return Ok(());
    }

    // 匹配接口名称，失败则给出列表
    let (iface, src_ip) = get_iface_by_name(if_name.as_str())
        .ok_or_else(|| raise_error!(__func__, "查不到指定接口"))?;
    let src_ip = src_ip.ok_or_else(|| raise_error!(__func__, "指定接口查不到 IPv4 地址"))?;

    // 检查 MAC 地址，应晚于 get_iface_and_ip 否则 list 不能给出正确提示
    let gw_mac = env::args()
        .nth(2)
        .ok_or_else(|| raise_error!(__func__, format!("缺少命令行参数:\n{}", usage.clone())))?;

    let mut rng = thread_rng();

    match send_l2(&iface, gw_mac.as_str(), &src_ip, &mut rng) {
        Ok(_) => {
            println!("pnet L2 发送 ... 成功!");
        }
        Err(err) => {
            println!("pnet L2 发送 ... 失败!\n{:?}", err);
        }
    }

    match send_l4(&src_ip, &mut rng) {
        Ok(_) => {
            println!("pnet L4 发送 ... 成功!");
        }
        Err(err) => {
            println!("pnet L4 发送 ... 失败!\n{:?}", err);
        }
    }

    Ok(())
}

// 实验表明
// windows 下不能用 l4 发送, 可以用 l2(非管理员), 但需要指明接口、路由器 mac, 不太方便
// linux 下可以用 l4(root) 发送, 相比于 l2(root) 更方便

/// 通过 pnet L2 通道发送
#[auto_func_name2]
fn send_l2(
    iface: &NetworkInterface,
    gw_mac: &str,
    src_ip: &Ipv4Addr,
    rng: &mut ThreadRng,
) -> Result<(), anyhow::Error> {
    //*

    let (mut tx, mut _rx) =
        create_l2_channel(iface).or_else(|err| raise_error!(__func__, "\n", err))?;

    let src_mac = iface
        .mac
        .ok_or_else(|| raise_error!(__func__, "无法获取源 MAC 地址"))?;
    let dst_mac = parse_mac(gw_mac);
    let dst_ip = Ipv4Addr::new(
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
    );
    let src_port = rng.gen::<u16>();
    let dst_port = rng.gen::<u16>();

    send_tcp(
        &mut tx,
        0,
        &src_mac,
        &dst_mac,
        src_ip,
        &dst_ip,
        src_port,
        dst_port,
        rng,
        |_x| false,
    )
    .or_else(|err| raise_error!(__func__, "\n", err))
}

/// 通过 pnet L4 通道发送
#[auto_func_name2]
fn send_l4(src_ip: &Ipv4Addr, mut rng: &mut ThreadRng) -> Result<(), anyhow::Error> {
    //*

    let (mut tx, mut _rx) = create_l4_channel().or_else(|err| raise_error!(__func__, "\n", err))?;

    let dst_ip = Ipv4Addr::new(
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
        rng.gen::<u8>(),
    );
    let src_port = rng.gen::<u16>();
    let dst_port = rng.gen::<u16>();

    let mut tx_buffer = [0u8; 20];
    let mut tx_packet = MutableTcpPacket::new(&mut tx_buffer)
        .ok_or_else(|| raise_error!(__func__, "无法创建 TcpPacket"))?;
    build_l4_tcp_packet(
        &mut tx_packet,
        &src_ip,
        &dst_ip,
        src_port,
        dst_port,
        &mut rng,
    );

    tx.send_to(tx_packet, IpAddr::V4(dst_ip))
        .or_else(|err| raise_error!(__func__, "\n", err))?;

    Ok(())
}
