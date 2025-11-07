use crate::TcpSlice;
use std::io;
use std::io::Cursor;
use std::net::Ipv4Addr;

#[derive(Eq, PartialEq, Hash, Debug)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

enum State {
    Closed,
    Listen,
    SynRcvd,
}

/// Send Sequence Space (RFC793 Fig4 in S3.2)
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update
    wl1: u32,
    // segment acknowledgment number used for last window update
    wl2: u32,
    // initial send sequence number
    iss: u32,
}

/// Receive Sequence Space (RFC793 Fig5 in S3.2)
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct ReceiveSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: TcpSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        eprintln!(
            "header_len={}, src_port={}, dst_port={}, sec={}, ack={}, data_offset={}, n_data={}",
            tcph.header_len(),
            tcph.source_port(),
            tcph.destination_port(),
            tcph.sequence_number(),
            tcph.acknowledgment_number(),
            tcph.data_offset(),
            data.len(),
        );

        if !tcph.syn() {
            eprintln!("mut be `rcv SYN`, but got syn packet");
            // must be `rcv SYN`
            return Ok(None);
        }

        let iss = 0;
        let c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
                iss: 0,
            },
            recv: ReceiveSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                up: false,
                wnd: tcph.window(),
            },
        };
        let mut buf = [0u8; 1054];
        let mut cursor = Cursor::new(&mut buf[..]);

        // establish the connection
        let mut syn_hdr = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        syn_hdr.acknowledgment_number = tcph.sequence_number();
        syn_hdr.syn = true;
        syn_hdr.ack = true;
        let ip = etherparse::Ipv4Header::new(
            syn_hdr.header_len_u16(),
            64,
            etherparse::IpNumber::TCP,
            [
                iph.destination()[0],
                iph.destination()[1],
                iph.destination()[2],
                iph.destination()[3],
            ],
            [
                iph.source()[0],
                iph.source()[1],
                iph.source()[2],
                iph.source()[3],
            ],
        )
        .unwrap();
        ip.write(&mut cursor)?;
        syn_hdr.write(&mut cursor)?;
        let used = cursor.position() as usize;
        let _ = nic.send(&buf[..used]);
        Ok(Some(c))
    }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: TcpSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        Ok(())
    }
}
