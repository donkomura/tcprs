use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("invalid header length `{0}`")]
    InvalidLengthErorr(usize),
    #[error("unknown")]
    Unknown,
}

#[derive(Debug)]
struct TcpSlice<'a> {
    header_len: usize,
    data: &'a [u8],
}

const TCP_HEADER_MIN_LEN: usize = 20;

impl<'a> TcpSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> std::result::Result<TcpSlice<'a>, HeaderError> {
        // TCP header length must be larger than 4B * 5 = 20B
        if slice.len() < TCP_HEADER_MIN_LEN {
            return Err(HeaderError::InvalidLengthErorr(slice.len()));
        }

        // get `data_offset` from the packet
        // and check the length
        // then we set the header_len to it
        // (because it takes into account `option` section)
        //
        // offset means the total number of words (32-bit) in header
        // so, it must be multiplied by 4 to representing as byte nubmer.
        let offset = usize::from((slice[12] & 0xf0) >> 2);
        if offset < TCP_HEADER_MIN_LEN {
            return Err(HeaderError::InvalidLengthErorr(slice.len()));
        }

        eprintln!("data offset {}", offset);

        Ok(Self {
            header_len: offset,
            data: slice,
        })
    }
}

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
                        eprintln!("{:?}", t);
                    }
                    Err(e) => {
                        eprintln!("weird pakcet: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("unknown packet: {}", e);
            }
        }
    }
}
