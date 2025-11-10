use etherparse::TcpHeaderSlice;
use std::collections::VecDeque;
use std::io;
use std::io::Cursor;
use std::io::Write;
use std::net::Ipv4Addr;

const CAP_READ: u8 = 0b00000001;
const CAP_WRITE: u8 = 0b00000010;

#[derive(Default)]
pub(crate) struct Available {
    flag: u8,
}

impl Available {
    pub fn is_readable(&self) -> bool {
        (self.flag & CAP_READ) > 0
    }
}

#[derive(Eq, PartialEq, Hash, Debug, Clone, Copy)]
pub struct Quad {
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
}

#[derive(PartialEq)]
enum State {
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::Estab
            | State::FinWait1
            | State::FinWait2
            | State::CloseWait
            | State::Closing => true,
            _ => false,
        }
    }
}

/// Send Sequence Space (RFC793 Fig4 in S3.2)
/// ```text
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
/// ```text
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

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
}

impl Connection {
    pub(crate) fn is_recv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: other state
            true
        } else {
            false
        }
    }
    pub(crate) fn availability(&self) -> Available {
        let mut x = Available::default();
        if self.is_recv_closed() || !self.incoming.is_empty() {
            x.flag |= CAP_READ;
        }
        // TODO: cap for write
        x
    }
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        eprintln!(
            "header_len={}, src_port={}, dst_port={}, seq={}, ack={}, data_offset={}, n_data={}",
            tcph.slice().len(),
            tcph.source_port(),
            tcph.destination_port(),
            tcph.sequence_number(),
            tcph.acknowledgment_number(),
            tcph.data_offset(),
            data.len(),
        );

        if !tcph.syn() {
            // eprintln!("mut be `rcv SYN`, but got syn packet");
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: ReceiveSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number().wrapping_add(1),
                wnd: tcph.window_size(),
                up: false,
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
            incoming: Default::default(),
            unacked: Default::default(),
            closed: false,
        };
        c.tcph.syn = true;
        c.tcph.ack = true;
        c.send_ack(nic, &[]);

        Ok(Some(c))
    }
    pub fn write(
        &mut self,
        nic: &mut tun_tap::Iface,
        seq: u32,
        payload: &[u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        let buf_len = buf.len();
        let mut cursor = Cursor::new(&mut buf[..]);

        self.tcph.sequence_number = seq;
        self.tcph.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf_len,
            self.tcph.header_len() as usize + self.iph.header_len() as usize + payload.len(),
        );
        // ip part
        self.iph
            .set_payload_len(size - self.iph.header_len() as usize)
            .unwrap();
        self.iph.write(&mut cursor)?;

        // tcp part
        self.tcph.checksum = self.tcph.calc_checksum_ipv4(&self.iph, &[]).unwrap();
        self.tcph.write(&mut cursor)?;

        // inner state part
        let payload_bytes = cursor.write(payload)?;
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcph.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcph.syn = false;
        }
        if self.tcph.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcph.fin = false;
        }
        self.send.nxt = next_seq;

        // flush the buffer to nic
        let used = cursor.position() as usize;
        let n = nic.send(&buf[..used])?;
        Ok(n)
    }
    pub fn send_ack(&mut self, nic: &mut tun_tap::Iface, buf: &[u8]) -> io::Result<usize> {
        self.write(nic, self.send.nxt, buf)
    }
    pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        //     FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        //     any unacceptable segment (out of window sequence number or
        //     unacceptible acknowledgment number) must elicit only an empty
        //     acknowledgment segment containing the current send-sequence number
        //     and an acknowledgment indicating the next sequence number expected
        //     to be received, and the connection remains in the same state.
        self.tcph.rst = true;
        // TODO: the ACK field is set to the sum of the sequence number and segment
        // length of the incoming segment
        self.tcph.acknowledgment_number = 0;
        self.iph.set_payload_len(self.tcph.header_len()).unwrap();
        self.write(nic, 0, &[])?;
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        _iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // check sequence number
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //   or
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        let seq = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.syn() {
            slen += 1;
        }
        if tcph.fin() {
            slen += 1;
        }
        let toe = self.recv.nxt.wrapping_add(self.recv.wnd.into());
        let valid_range = if slen == 0 {
            if self.recv.wnd == 0 {
                seq != self.recv.nxt
            } else {
                is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq, toe)
            }
        } else {
            self.recv.wnd != 0
                && (is_between_wrapped(self.recv.nxt.wrapping_sub(1), seq, toe)
                    || is_between_wrapped(
                        self.recv.nxt.wrapping_sub(1),
                        seq.wrapping_add(slen).wrapping_sub(1),
                        toe,
                    ))
        };

        if !valid_range {
            eprintln!(
                "invalid range: seq={}, slen={}, recv.nxt={}, recv.wnd={}, toe={}",
                seq, slen, self.recv.nxt, self.recv.wnd, toe
            );
            return Ok(self.availability());
        }

        if !tcph.ack() {
            if tcph.syn() {
                // got SYN in handshake, then we consume seq
                assert!(data.is_empty());
                self.recv.nxt = seq.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        // check the ACK field
        // check if the packet is acceptable ack
        // SND.UNA < SEG.ACK =< SND.NXT
        let ack = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ack,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            } else {
                self.send_rst(nic);
                return Ok(self.availability());
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ack, self.send.nxt.wrapping_add(1)) {
                self.send.una = ack;
            }

            // TODO: the acked data in queue has to be deleted
            // TODO: notify
            // TODO: update window
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our fin is acked
                self.state = State::FinWait2;
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // TODO: only read that we haven't read
            let mut unread_at = self.recv.nxt.wrapping_sub(seq) as usize;
            if unread_at > data.len() {
                // reset pointer
                unread_at = 0;
            }
            self.incoming.extend(&data[unread_at..]);

            self.recv.nxt = seq.wrapping_add(data.len() as u32);

            self.send_ack(nic, &[])?;
        }

        // check the queue
        if !data.is_empty() {
            // TODO: set incoming
        }

        if tcph.fin() {
            match self.state {
                State::SynRcvd | State::Estab => {
                    self.state = State::CloseWait;
                }
                State::FinWait1 => {
                    if tcph.ack() && self.send.una == self.send.iss + 2 {
                        // our fin is acked
                        self.state = State::TimeWait;
                    } else {
                        self.state = State::Closing;
                        self.send_ack(nic, &[])?;
                    }
                }
                State::FinWait2 => {
                    // done with the conneciton
                    self.write(nic, 0, &[])?;
                    self.state = State::TimeWait;
                }
                _ => {}
            }
        }

        Ok(self.availability())
    }
    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }

    pub(crate) fn send_fin(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcph.fin = true;
        self.write(nic, self.send.nxt, &[])?;
        match self.state {
            State::Estab => {
                self.state = State::FinWait1;
            }
            _ => {}
        }
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323 S2.3:
    //   TCP determines if a data segment is "old" or "new" by testing
    //   whether its sequence number is within 2**31 bytes of the left edge
    //   of the window, and if it is not, discarding the data as "old".  To
    //   insure that new data is never mistakenly considered old and vice-
    //   versa, the left edge of the sender's window has to be at most
    //   2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, target: u32, end: u32) -> bool {
    wrapping_lt(start, target) && wrapping_lt(target, end)
}

/*
// check START < TARGET <= END
fn is_between_wrapped(start: u32, target: u32, end: u32) -> bool {
    if start == end {
        return target == start;
    } else if start < target {
        return target <= end || (end < start && end <= target);
    }
    end >= target && start >= end
}
*/
