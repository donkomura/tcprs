mod tcp;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::*;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

const SENDQUE_SIZE: usize = 1024;

#[derive(Default)]
struct Condition {
    cond_pending: Condvar,
    cond_recv: Condvar,
    manager: Mutex<ConnectionManager>,
}

type InterfaceHandle = Arc<Condition>;

pub struct Interface {
    ih: Option<InterfaceHandle>,        // nic handler
    jh: Option<thread::JoinHandle<()>>, // packet processing thread
}

#[derive(Default)]
struct ConnectionManager {
    terminate: bool,
    connections: HashMap<tcp::Quad, tcp::Connection>,
    pendings: HashMap<u16, VecDeque<tcp::Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut nic = nic;
    let ih = ih;
    let mut buf = [0u8; 1504];
    loop {
        // TODO: block point: to terminate, we need to set timer
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
                        let mut cmg = ih.manager.lock().unwrap();
                        let mut cm = &mut *cmg;
                        let q = tcp::Quad {
                            src: (src_ip, tcp_hdr.source_port()),
                            dst: (dst_ip, tcp_hdr.destination_port()),
                        };
                        match cm.connections.entry(q) {
                            Entry::Occupied(mut c) => {
                                let a = c.get_mut().on_packet(
                                    &mut nic,
                                    ip_hdr,
                                    tcp_hdr,
                                    &buf[idx_payload..eth_nbytes],
                                )?;

                                drop(cmg);

                                if a.is_readable() {
                                    ih.cond_recv.notify_all()
                                }
                            }
                            Entry::Vacant(e) => {
                                if let Some(pending) =
                                    cm.pendings.get_mut(&tcp_hdr.destination_port())
                                {
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic,
                                        ip_hdr,
                                        tcp_hdr,
                                        &buf[idx_payload..eth_nbytes],
                                    )? {
                                        e.insert(c);
                                        pending.push_back(q);
                                        drop(cmg);
                                        ih.cond_pending.notify_all()
                                    }
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

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun", tun_tap::Mode::Tun)?;
        let ih: InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || {
                packet_loop(nic, ih);
            })
        };
        Ok(Interface {
            ih: Some(ih),
            jh: Some(jh),
        })
    }
    pub fn bind(&mut self, port: u16) -> Result<TcpListener> {
        use std::collections::hash_map::Entry;

        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
        match cm.pendings.entry(port) {
            Entry::Vacant(e) => {
                e.insert(Vec::new().into());
            }
            Entry::Occupied(_) => {
                return Err(io::Error::new(io::ErrorKind::AddrInUse, "already bound"));
            }
        }
        drop(cm);
        Ok(TcpListener {
            port,
            h: self.ih.as_mut().unwrap().clone(),
        })
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh.take().expect("already dropped").join().unwrap();
    }
}

pub struct TcpStream {
    quad: tcp::Quad,
    h: InterfaceHandle,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        // TODO: send FIN on cm.connections[quad]
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        c.close()
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated")
            })?;

            if c.is_recv_closed() && c.incoming.is_empty() {
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                let mut nbytes = 0;
                // reading bytes from stream
                let (head, tail) = c.incoming.as_slices();
                let hread = std::cmp::min(buf.len(), head.len());
                buf[..hread].copy_from_slice(&head[..hread]);
                nbytes += hread;
                let tread = std::cmp::min(buf.len() - nbytes, tail.len());
                buf[nbytes..(nbytes + tread)].copy_from_slice(&tail[..tread]);
                nbytes += tread;
                drop(c.incoming.drain(..nbytes));
                return Ok(nbytes);
            }
            cm = self.h.cond_recv.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut ih = self.h.manager.lock().unwrap();
        let c = ih.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated")
        })?;

        if c.unacked.len() >= SENDQUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes in buffer",
            ));
        }

        let nbytes = std::cmp::min(SENDQUE_SIZE - c.unacked.len(), buf.len());
        c.unacked.extend(buf[..nbytes].iter());
        Ok(nbytes)
    }
    fn flush(&mut self) -> Result<()> {
        let mut ih = self.h.manager.lock().unwrap();
        let c = ih.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionAborted, "stream was terminated")
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes in buffer",
            ))
        }
    }
}

pub struct TcpListener {
    port: u16,
    h: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();

        let pendings = cm
            .pendings
            .remove(&self.port)
            .expect("port closed with active listener");

        for quad in pendings {
            unimplemented!()
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        loop {
            let mut cm = self.h.manager.lock().unwrap();

            if let Some(quad) = cm
                .pendings
                .get_mut(&self.port)
                .expect("port closed with active listener")
                .pop_front()
            {
                return Ok(TcpStream {
                    quad,
                    h: self.h.clone(),
                });
            }
            cm = self.h.cond_pending.wait(cm).unwrap();
        }
    }
}
