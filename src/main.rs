use std::io;
use tcprs::TcpSlice;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let eth_nbytes = nic.recv(&mut buf[..])?;
        let _eth_flag = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if the packet is not ipv4, then drop
        if eth_proto != 0x0800 {
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..eth_nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                if proto != etherparse::IpNumber::TCP {
                    eprintln!("not a tcp packet, so drop it (protocol={})", proto.0);
                    continue;
                }
                eprintln!(
                    "{} => {} {} plen={:?}",
                    src,
                    dst,
                    proto.0,
                    p.payload_len().unwrap()
                );

                match TcpSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    Ok(t) => {
                        eprintln!(
                            "header_len={}, src_port={}, dst_port={}, sec={}, ack={}, data_offset={}",
                            t.header_len(),
                            t.source_port(),
                            t.destination_port(),
                            t.sequence_number(),
                            t.acknowledgment_number(),
                            t.data_offset()
                        );
                    }
                    Err(e) => {
                        eprintln!("weird packet: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("unknown packet: {}", e);
            }
        }
    }
}
