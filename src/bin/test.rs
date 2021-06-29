use rand::thread_rng;
use rawsocket_helper::{
    out_going::{
        get_all, get_gw, get_iface, get_iface_by_ip, get_ifaces, get_neighbour_mac,
        get_out_going_ip,
    },
    send::{create_channel, send_tcp},
    sys::is_root,
};
use std::net::Ipv4Addr;

fn main() {
    println!("is_root: {}", is_root());

    for (name, ipv4) in get_ifaces() {
        println!("{}, {}", name, ipv4);
    }

    let src_ip = get_out_going_ip().unwrap();
    let (src_if, src_if_name) = get_iface_by_ip(&src_ip.to_string()).unwrap();
    let dst_gw = get_gw(src_if).unwrap();
    let (src_mac, dst_mac) = get_neighbour_mac(src_if, &src_ip, &dst_gw).unwrap();
    println!("src_if: {} {}", src_if, src_if_name);
    println!("src_ip: {}", src_ip);
    println!("dst_gw: {}", dst_gw);
    println!("src_mac: {}", src_mac);
    println!("dst_mac: {}", dst_mac);

    let og = get_all().unwrap();
    let (mut tx, _) = create_channel(&get_iface(og.if_index).unwrap()).unwrap();
    let mut rng = thread_rng();
    send_tcp(
        &mut tx,
        0, // body 长度, 缺省填充为 0
        &og.src_mac,
        &og.dst_mac,
        &og.src_ip,
        &Ipv4Addr::new(8, 8, 8, 8),
        1234,
        53,
        &mut rng,
        |_x| false, // 修改生成的 TCP 报文, 如果修改 IP 头, 需同时修改校验和,
                    // 如果修改 TCP 部分, 返回 true 会自动更新校验和, _x 是从 l2 开始的数据
    )
    .unwrap();
}
