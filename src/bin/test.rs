use rawsocket_helper::prelude::{
    get_ifaces, get_neighbour_mac, get_out_going_gw, get_out_going_if_by_ip, get_out_going_ip,
    is_root,
};

fn main() {
    println!("is_root: {}", is_root());

    for (name, ipv4) in get_ifaces() {
        println!("{}, {}", name, ipv4);
    }

    let out_going_ip = get_out_going_ip().unwrap();
    let (out_going_if, out_going_if_name) =
        get_out_going_if_by_ip(&out_going_ip.to_string()).unwrap();
    let out_going_gw = get_out_going_gw(out_going_if).unwrap();
    let (out_going_src_mac, out_going_dst_mac) =
        get_neighbour_mac(out_going_if, &out_going_ip, &out_going_gw).unwrap();
    println!("out_going_if: {} {}", out_going_if, out_going_if_name);
    println!("out_going_ip: {}", out_going_ip);
    println!("out_going_gw: {}", out_going_gw);
    println!("out_going_src_mac: {}", out_going_src_mac);
    println!("out_going_dst_mac: {}", out_going_dst_mac);
}
