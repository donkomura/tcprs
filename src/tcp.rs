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
    iph: etherparse::Ipv4Header,
    tcph: etherparse::TcpHeader,
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
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                una: iss,
                nxt: iss.wrapping_add(1),
                wnd: wnd,
                up: false,
                wl1: 0,
                wl2: 0,
                iss: 0,
            },
            recv: ReceiveSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number().wrapping_add(1),
                up: false,
                wnd: tcph.window(),
            },
            tcph: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            iph: etherparse::Ipv4Header::new(
                0, // payload length will be set in write()
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
            .unwrap(),
        };
        c.tcph.syn = true;
        c.tcph.ack = true;
        c.write(nic, c.send.nxt)?;

        Ok(Some(c))
    }
    pub fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32) -> io::Result<usize> {
        let mut buf = [0u8; 1054];

        self.tcph.sequence_number = seq;
        self.tcph.acknowledgment_number = self.recv.nxt;

        // Set the payload length in IP header
        self.iph
            .set_payload_len(self.tcph.header_len_u16() as usize)
            .unwrap();

        // Calculate TCP checksum
        self.tcph.checksum = self.tcph.calc_checksum_ipv4(&self.iph, &[]).unwrap();

        let mut cursor = Cursor::new(&mut buf[..]);
        self.iph.write(&mut cursor)?;
        self.tcph.write(&mut cursor)?;
        let used = cursor.position() as usize;
        let n = nic.send(&buf[..used])?;
        Ok(n)
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
