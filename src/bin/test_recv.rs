use anyhow::anyhow;
use pnet::{datalink::NetworkInterface, transport::tcp_packet_iter};
use python_comm::prelude::raise_error;
use python_comm_macros::auto_func_name2;
use rawsocket_helper::{
    out_going::{get_iface_by_name, get_ifaces},
    send::{create_l2_channel, create_l4_channel},
};
use std::{
    env,
    thread::{spawn, JoinHandle},
};

#[cfg(target_os = "windows")]
use pcap::{Active, Capture, Device};

/// 创建 pcap 通道, 不打算开放给 recv 模块
#[cfg(target_os = "windows")]
#[auto_func_name2]
fn create_pcap_channel(iface: Device) -> Result<Capture<Active>, anyhow::Error> {
    Capture::from_device(iface)
        .and_then(|iface| iface.immediate_mode(true).open())
        .or_else(|err| raise_error!(__func__, "\n", err))
}

/// 获取接口, 不打算开放给 recv 模块
#[cfg(target_os = "windows")]
#[auto_func_name2]
fn get_pcap_by_name(iface_name: &str) -> Result<Device, anyhow::Error> {
    // 指定接口
    Device::list()
        .or_else(|err| raise_error!(__func__, "\n", err))?
        .into_iter()
        .find(|x| x.name == iface_name)
        .ok_or_else(|| raise_error!(__func__, "查不到指定接口"))
}

/// 入口
///
/// 实验表明
/// windows 下不能用 l4 接收, 可以用 l2 接收, 可以用 pcap 接收
/// linux   下可以用 l4 接收, 可以用 l2 接收, pcap 需要额外安装未尝试不推荐
fn main() {
    if let Err(e) = main_error() {
        println!("{}", e)
    }
}

/// 含错误信息的入口
#[auto_func_name2]
fn main_error() -> Result<(), anyhow::Error> {
    println!("命令: {}", env::args().collect::<Vec<String>>().join(" "));

    // 程序名, 用法
    let app_name = env::args().nth(0).unwrap_or(String::from("app"));
    let usage = env::args().nth(1).ok_or(anyhow!(
        "{}\n{}\n{}",
        "用法:",
        format!("    {} iface_name - 测试不同的接收方案", app_name),
        format!("    {} list - 列出接口名称及 IP", app_name),
    ))?;

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

    // 匹配接口名称
    let (iface, _src_ip) =
        get_iface_by_name(if_name.as_str()).ok_or_else(|| raise_error!(__func__, "查不到指定接口"))?;

    let recv2 = recv_l2(&iface);
    match &recv2 {
        Ok(_) => {
            println!("pnet L2 通道 ... 成功!");
        }
        Err(err) => {
            println!("pnet L2 通道 ... 失败!\n{:?}", err);
        }
    }

    let recv4 = recv_l4();
    match &recv4 {
        Ok(_) => {
            println!("pnet L4 通道 ... 成功!");
        }
        Err(err) => {
            println!("pnet L4 通道 ... 失败!\n{:?}", err);
        }
    }

    #[cfg(target_os = "windows")]
    let iface = get_pcap_by_name(if_name.as_str()).or_else(|err| raise_error!(__func__, "\n", err))?;

    #[cfg(target_os = "windows")]
    let recvp = recv_pcap(iface);

    #[cfg(target_os = "windows")]
    match &recvp {
        Ok(_) => {
            println!("pcap    通道 ... 成功!");
        }
        Err(err) => {
            println!("pcap    通道 ... 失败!\n{:?}", err);
        }
    }

    if let Ok(recv) = recv2 {
        let _ret = recv.join();
    }

    if let Ok(recv) = recv4 {
        let _ret = recv.join();
    }

    #[cfg(target_os = "windows")]
    if let Ok(recv) = recvp {
        let _ret = recv.join();
    }

    Ok(())
}

/// 通过 pnet L2 通道接收
fn recv_l2(iface: &NetworkInterface) -> Result<JoinHandle<u32>, anyhow::Error> {
    let (mut _tx, mut rx) = create_l2_channel(iface)?;

    Ok(spawn(move || loop {
        match rx.next() {
            Ok(_rx_packet) => {
                println!("pnet L2 接收 ... 成功!");
            }
            Err(err) => {
                println!("pnet L2 接收 ... 失败!\n{:?}", err);
            }
        }
        // 实际代码 no break
        break 0;
    }))
}

/// 通过 pnet L4 通道接收
fn recv_l4() -> Result<JoinHandle<u32>, anyhow::Error> {
    let (mut _tx, mut rx) = create_l4_channel()?;

    Ok(spawn(move || {
        let mut iter = tcp_packet_iter(&mut rx);
        loop {
            match iter.next() {
                Ok((_rx_packet, _addr)) => {
                    println!("pnet L4 接收 ... 成功!");
                }
                Err(err) => {
                    println!("pnet L4 接收 ... 失败!\n{:?}", err);
                }
            }
            // 实际代码 no break
            break 0;
        }
    }))
}

/// 通过 pcap 通道接收
#[cfg(target_os = "windows")]
fn recv_pcap(iface: Device) -> Result<JoinHandle<u32>, anyhow::Error> {
    // 通道
    let mut cap = create_pcap_channel(iface)?;

    Ok(spawn(move || loop {
        match cap.next() {
            Ok(_rx_packet) => {
                println!("pcap    接收 ... 成功!");
            }
            Err(err) => {
                eprintln!("pcap    接收 ... 失败!\n{:?}", err);
            }
        };
        // 实际代码 no break
        break 0;
    }))
}
