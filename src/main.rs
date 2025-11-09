use std::io;
use std::io::{Read, Write};
use std::thread;

fn main() -> io::Result<()> {
    let mut i = tcprs::Interface::new()?;
    let mut l1 = i.bind(8000)?;
    let jh = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection!");
            stream.write(b"hello").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data!");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });
    jh.join().unwrap();
    Ok(())
}
