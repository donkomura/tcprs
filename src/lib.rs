use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("invalid header length `{0}`")]
    InvalidLengthError(usize),
    #[error("unknown")]
    Unknown,
}

#[derive(Debug)]
pub struct TcpSlice<'a> {
    header_len: usize,
    slice: &'a [u8],
}

const TCP_HEADER_MIN_LEN: usize = 20;

impl<'a> TcpSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> std::result::Result<TcpSlice<'a>, HeaderError> {
        // TCP header length must be larger than 4B * 5 = 20B
        if slice.len() < TCP_HEADER_MIN_LEN {
            return Err(HeaderError::InvalidLengthError(slice.len()));
        }

        // get `data_offset` from the packet
        // and check the length
        // then we set the header_len to it
        // (because it takes into account `option` section)
        //
        // offset means the total number of words (32-bit) in header
        // so, it must be multiplied by 4 to representing as byte number.
        let offset = usize::from((slice[12] & 0xf0) >> 2);
        if offset < TCP_HEADER_MIN_LEN {
            return Err(HeaderError::InvalidLengthError(slice.len()));
        }

        Ok(Self {
            header_len: offset,
            slice: slice,
        })
    }
    pub fn header_len(&self) -> usize {
        self.header_len
    }
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.slice[0], self.slice[1]])
    }
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.slice[2], self.slice[3]])
    }
    pub fn sequence_number(&self) -> u32 {
        u32::from_be_bytes([self.slice[4], self.slice[5], self.slice[6], self.slice[7]])
    }
    pub fn acknowledgment_number(&self) -> u32 {
        u32::from_be_bytes([self.slice[8], self.slice[9], self.slice[10], self.slice[11]])
    }
    pub fn data_offset(&self) -> u8 {
        (self.slice[12] & 0xf0) >> 4
    }
    pub fn urg(&self) -> bool {
        0 != (self.slice[13] & 0b0010_0000)
    }
    pub fn ack(&self) -> bool {
        0 != (self.slice[13] & 0b0001_0000)
    }
    pub fn psh(&self) -> bool {
        0 != (self.slice[13] & 0b0000_1000)
    }
    pub fn rst(&self) -> bool {
        0 != (self.slice[13] & 0b0000_0100)
    }
    pub fn syn(&self) -> bool {
        0 != (self.slice[13] & 0b0000_0010)
    }
    pub fn fin(&self) -> bool {
        0 != (self.slice[13] & 0b0000_0001)
    }
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.slice[14], self.slice[15]])
    }
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.slice[16], self.slice[17]])
    }
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.slice[18], self.slice[19]])
    }
    pub fn options(&self) -> &[u8] {
        &self.slice[TCP_HEADER_MIN_LEN..self.header_len]
    }
    pub fn calc_checksum(
        &self,
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
    ) -> std::result::Result<u16, CheckSumValueError> {
        let mut checksum = CheckSum16::default();
        checksum
            .add_16bytes(src_ip) // source ip
            .add_16bytes(dst_ip) // destination ip
            .add_2bytes([0u8, 6u8]) // blank and protocol
            .add_4bytes((self.slice.len() as u32).to_be_bytes()); // TCP length

        // add TCP header without checksum
        Ok(checksum
            .add_slice(&self.slice[..16])
            .add_slice(&self.slice[18..])
            .ones_complement())
    }

    pub fn slice(&self) -> &[u8] {
        &self.slice
    }
}

#[derive(Error, Debug)]
pub enum CheckSumValueError {
    #[error("unknown")]
    Unknown,
}

#[derive(Default, Debug, Copy, Clone)]
struct CheckSum16 {
    sum: u32,
}

impl CheckSum16 {
    fn add_2bytes(&mut self, d: [u8; 2]) -> CheckSum16 {
        let (sum, carry) = self.sum.overflowing_add(u32::from(u16::from_ne_bytes(d)));
        Self {
            sum: sum + (carry as u32),
        }
    }
    fn add_4bytes(&mut self, d: [u8; 4]) -> CheckSum16 {
        let (sum, carry) = self.sum.overflowing_add(u32::from_ne_bytes(d));
        Self {
            sum: sum + (carry as u32),
        }
    }
    fn add_8bytes(&mut self, d: [u8; 8]) -> CheckSum16 {
        self.add_4bytes([d[0], d[1], d[2], d[3]])
            .add_4bytes([d[4], d[5], d[6], d[7]])
    }
    fn add_16bytes(&mut self, d: [u8; 16]) -> CheckSum16 {
        self.add_8bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
            .add_8bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]])
    }
    fn add_slice(&mut self, slice: &[u8]) -> CheckSum16 {
        let end = slice.len() - (slice.len() % 4);
        for i in (0..end).step_by(4) {
            *self = self.add_4bytes([slice[i], slice[i + 1], slice[i + 2], slice[i + 3]]);
        }
        // bytes left in the slice is 0, 1, 2, 3
        if slice.len() - end >= 2 {
            *self = self.add_2bytes([slice[end], slice[end + 1]]);
        }
        // bytes left in the slice is 0, 1
        if slice.len() % 2 != 0 {
            *self = self.add_2bytes([slice[slice.len() - 1], 0]);
        }
        *self
    }
    fn ones_complement(&self) -> u16 {
        // calculate the sum of lower u8 value and upper u8 value
        let first: u32 = ((self.sum >> 16) & 0xffff) + (self.sum & 0xffff);
        // take into account of the carry in the `first` calculation
        let second = (((first >> 16) & 0xffff) + (first & 0xffff)) as u16;

        // return ones complement of the sum
        // use native endian
        !second
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod tcp_slice {
        use super::*;

        #[test]
        fn parse_syn_packet() {
            let mut packet = vec![0u8; 20];
            packet[0] = 0x1F;
            packet[1] = 0x90;
            packet[2] = 0x00;
            packet[3] = 0x50;
            packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
            packet[8..12].copy_from_slice(&0x00000000u32.to_be_bytes());
            packet[12] = 0x50;
            packet[13] = 0b0000_0010;
            packet[14..16].copy_from_slice(&8192u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0xABCDu16.to_be_bytes());
            packet[18..20].copy_from_slice(&0u16.to_be_bytes());

            let our_tcp = TcpSlice::from_slice(&packet).unwrap();
            let etherparse_tcp = etherparse::TcpSlice::from_slice(&packet).unwrap();

            assert_eq!(our_tcp.source_port(), etherparse_tcp.source_port());
            assert_eq!(
                our_tcp.destination_port(),
                etherparse_tcp.destination_port()
            );
            assert_eq!(our_tcp.sequence_number(), etherparse_tcp.sequence_number());
            assert_eq!(
                our_tcp.acknowledgment_number(),
                etherparse_tcp.acknowledgment_number()
            );
            assert_eq!(our_tcp.data_offset(), etherparse_tcp.data_offset());
            assert_eq!(our_tcp.syn(), etherparse_tcp.syn());
            assert_eq!(our_tcp.ack(), etherparse_tcp.ack());
            assert_eq!(our_tcp.window(), etherparse_tcp.window_size());
            assert_eq!(our_tcp.checksum(), etherparse_tcp.checksum());
        }

        #[test]
        fn parse_syn_ack_packet() {
            let mut packet = vec![0u8; 20];
            packet[0..2].copy_from_slice(&80u16.to_be_bytes());
            packet[2..4].copy_from_slice(&8080u16.to_be_bytes());
            packet[4..8].copy_from_slice(&0x87654321u32.to_be_bytes());
            packet[8..12].copy_from_slice(&0x12345679u32.to_be_bytes());
            packet[12] = 0x50;
            packet[13] = 0b0001_0010;
            packet[14..16].copy_from_slice(&65535u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0x1234u16.to_be_bytes());
            packet[18..20].copy_from_slice(&0u16.to_be_bytes());

            let our_tcp = TcpSlice::from_slice(&packet).unwrap();
            let etherparse_tcp = etherparse::TcpSlice::from_slice(&packet).unwrap();

            assert_eq!(our_tcp.source_port(), etherparse_tcp.source_port());
            assert_eq!(
                our_tcp.destination_port(),
                etherparse_tcp.destination_port()
            );
            assert_eq!(our_tcp.sequence_number(), etherparse_tcp.sequence_number());
            assert_eq!(
                our_tcp.acknowledgment_number(),
                etherparse_tcp.acknowledgment_number()
            );
            assert_eq!(our_tcp.syn(), etherparse_tcp.syn());
            assert_eq!(our_tcp.ack(), etherparse_tcp.ack());
            assert_eq!(our_tcp.window(), etherparse_tcp.window_size());
        }

        #[test]
        fn parse_fin_ack_packet() {
            let mut packet = vec![0u8; 20];
            packet[0..2].copy_from_slice(&12345u16.to_be_bytes());
            packet[2..4].copy_from_slice(&80u16.to_be_bytes());
            packet[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
            packet[8..12].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
            packet[12] = 0x50;
            packet[13] = 0b0001_0001;
            packet[14..16].copy_from_slice(&16384u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0x9999u16.to_be_bytes());
            packet[18..20].copy_from_slice(&0u16.to_be_bytes());

            let our_tcp = TcpSlice::from_slice(&packet).unwrap();
            let etherparse_tcp = etherparse::TcpSlice::from_slice(&packet).unwrap();

            assert_eq!(our_tcp.source_port(), etherparse_tcp.source_port());
            assert_eq!(
                our_tcp.destination_port(),
                etherparse_tcp.destination_port()
            );
            assert_eq!(our_tcp.sequence_number(), etherparse_tcp.sequence_number());
            assert_eq!(
                our_tcp.acknowledgment_number(),
                etherparse_tcp.acknowledgment_number()
            );
            assert_eq!(our_tcp.fin(), etherparse_tcp.fin());
            assert_eq!(our_tcp.ack(), etherparse_tcp.ack());
            assert_eq!(our_tcp.window(), etherparse_tcp.window_size());
            assert_eq!(our_tcp.checksum(), etherparse_tcp.checksum());
        }
    }

    mod tcp_checksum {
        use super::*;

        #[test]
        fn calc_checksum_ipv4_syn() {
            let mut packet = vec![0u8; 20];
            packet[0..2].copy_from_slice(&8080u16.to_be_bytes());
            packet[2..4].copy_from_slice(&80u16.to_be_bytes());
            packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
            packet[8..12].copy_from_slice(&0x00000000u32.to_be_bytes());
            packet[12] = 0x50;
            packet[13] = 0b0000_0010;
            packet[14..16].copy_from_slice(&8192u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0x0000u16.to_be_bytes());
            packet[18..20].copy_from_slice(&0u16.to_be_bytes());

            let tcp = TcpSlice::from_slice(&packet).unwrap();

            let src_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 100];
            let dst_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1];

            let checksum = tcp.calc_checksum(src_ip, dst_ip).unwrap();

            assert_ne!(checksum, 0, "Checksum should not be zero for valid packet");
        }

        #[test]
        fn calc_checksum_ipv4_with_data() {
            let mut packet = vec![0u8; 20];
            packet[0..2].copy_from_slice(&12345u16.to_be_bytes());
            packet[2..4].copy_from_slice(&80u16.to_be_bytes());
            packet[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
            packet[8..12].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
            packet[12] = 0x50;
            packet[13] = 0b0001_1000;
            packet[14..16].copy_from_slice(&65535u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0x0000u16.to_be_bytes());
            packet[18..20].copy_from_slice(&100u16.to_be_bytes());

            let slice = b"Hello, TCP!";
            let mut full_packet = packet.clone();
            full_packet.extend_from_slice(slice);

            let tcp = TcpSlice::from_slice(&full_packet).unwrap();

            let src_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 1];
            let dst_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 2];

            let checksum = tcp.calc_checksum(src_ip, dst_ip).unwrap();

            assert_ne!(
                checksum, 0,
                "Checksum should not be zero for packet with slice"
            );
        }

        #[test]
        fn calc_checksum_ipv6() {
            let mut packet = vec![0u8; 20];
            packet[0..2].copy_from_slice(&443u16.to_be_bytes());
            packet[2..4].copy_from_slice(&54321u16.to_be_bytes());
            packet[4..8].copy_from_slice(&0x11111111u32.to_be_bytes());
            packet[8..12].copy_from_slice(&0x22222222u32.to_be_bytes());
            packet[12] = 0x50;
            packet[13] = 0b0001_0000;
            packet[14..16].copy_from_slice(&32768u16.to_be_bytes());
            packet[16..18].copy_from_slice(&0x0000u16.to_be_bytes());
            packet[18..20].copy_from_slice(&0u16.to_be_bytes());

            let tcp = TcpSlice::from_slice(&packet).unwrap();

            let src_ip = [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ];
            let dst_ip = [
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ];

            let checksum = tcp.calc_checksum(src_ip, dst_ip).unwrap();

            assert_ne!(checksum, 0, "Checksum should not be zero for IPv6 packet");
        }
    }

    mod checksum {
        use super::*;

        #[test]
        fn add_2bytes() {
            assert_eq!(
                !u16::from_ne_bytes([0x00, 0xff]),
                CheckSum16::default()
                    .add_2bytes([0x00, 0xff])
                    .ones_complement()
            );
            assert_eq!(
                !u16::from_ne_bytes([0xff, 0x10]),
                CheckSum16::default()
                    .add_2bytes([0xff, 0x10])
                    .ones_complement()
            );
            assert_eq!(
                !u16::from_ne_bytes([0xff, 0xff]),
                CheckSum16::default()
                    .add_2bytes([0xff, 0xff])
                    .ones_complement()
            );
        }

        #[test]
        fn add_4bytes() {
            assert_eq!(
                !(u16::from_ne_bytes([0x11, 0x22]) + u16::from_ne_bytes([0x33, 0x44])),
                CheckSum16::default()
                    .add_4bytes([0x11, 0x22, 0x33, 0x44])
                    .ones_complement()
            );
        }

        #[test]
        fn add_8bytes() {
            assert_eq!(
                !(u16::from_ne_bytes([0x12, 0x34])
                    + u16::from_ne_bytes([0x56, 0x78])
                    + u16::from_ne_bytes([0x23, 0x22])
                    + u16::from_ne_bytes([0x34, 0x11])),
                CheckSum16::default()
                    .add_8bytes([0x12, 0x34, 0x56, 0x78, 0x23, 0x22, 0x34, 0x11])
                    .ones_complement()
            );
        }

        #[test]
        fn add_16bytes() {
            let slice = [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                0x27, 0x28,
            ];

            let result = CheckSum16::default().add_16bytes(slice).ones_complement();

            let expected = !(u16::from_ne_bytes([0x11, 0x12])
                + u16::from_ne_bytes([0x13, 0x14])
                + u16::from_ne_bytes([0x15, 0x16])
                + u16::from_ne_bytes([0x17, 0x18])
                + u16::from_ne_bytes([0x21, 0x22])
                + u16::from_ne_bytes([0x23, 0x24])
                + u16::from_ne_bytes([0x25, 0x26])
                + u16::from_ne_bytes([0x27, 0x28]));

            assert_eq!(result, expected);
        }
        #[test]
        fn add_slice() {
            assert_eq!(
                !u16::from_ne_bytes([0x12, 0x34]),
                CheckSum16::default()
                    .add_slice(&[0x12, 0x34])
                    .ones_complement()
            );
        }

        #[test]
        fn add_slice_5bytes() {
            let result = CheckSum16::default()
                .add_slice(&[0x11, 0x22, 0x33, 0x44, 0x55])
                .ones_complement();

            let expected = !(u16::from_ne_bytes([0x11, 0x22])
                + u16::from_ne_bytes([0x33, 0x44])
                + u16::from_ne_bytes([0x55, 0x00]));
            assert_eq!(result, expected);
        }
    }
}
