use std::collections::HashMap;
use std::io;
// use tcprs::TcpSlice;
use etherparse::TcpSlice;

mod tcp;

fn main() -> io::Result<()> {
    let mut connections: HashMap<tcp::Quad, tcp::Connection> = Default::default();
    let mut nic = tun_tap::Iface::without_packet_info("tun", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let eth_nbytes = nic.recv(&mut buf[..])?;
        // let _eth_flag = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // // if the packet is not ipv4, then drop
        // if eth_proto != 0x0800 {
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..eth_nbytes]) {
            Ok(ip_hdr) => {
                let src_ip = ip_hdr.source_addr();
                let dst_ip = ip_hdr.destination_addr();
                if ip_hdr.protocol() != etherparse::IpNumber::TCP {
                    eprintln!(
                        "not a tcp packet, so drop it (protocol={})",
                        ip_hdr.protocol().0
                    );
                    continue;
                }
                eprintln!(
                    "{} => {} {} plen={:?}",
                    src_ip,
                    dst_ip,
                    ip_hdr.protocol().0,
                    ip_hdr.payload_len().unwrap()
                );

                match etherparse::TcpHeaderSlice::from_slice(&buf[ip_hdr.slice().len()..eth_nbytes])
                {
                    Ok(tcp_hdr) => {
                        use std::collections::hash_map::Entry;
                        let idx_payload = ip_hdr.slice().len() + tcp_hdr.slice().len();
                        match connections.entry(tcp::Quad {
                            src: (src_ip, tcp_hdr.source_port()),
                            dst: (dst_ip, tcp_hdr.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(
                                    &mut nic,
                                    ip_hdr,
                                    tcp_hdr,
                                    &buf[idx_payload..eth_nbytes],
                                )?;
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_hdr,
                                    tcp_hdr,
                                    &buf[idx_payload..eth_nbytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("weird packet: {}", e);
                    }
                }
            }
            Err(_) => {
                // eprintln!("unknown packet: {}", e);
            }
        }
    }
}
