use byteorder::{NetworkEndian, WriteBytesExt};
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{do_parse, IResult, call, take};
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq, Clone)]
pub struct Tcp {
    source:          u16,
    destination:     u16,
    sequence:        u32,
    acknowledgement: u32,
    data_offset:     u8,
    ns:  u8,
    cwr: u8,
    ece: u8,
    urg: u8,
    ack: u8,
    psh: u8,
    rst: u8,
    syn: u8,
    fin: u8,
    window_size: u16,
    checksum:    u16,
    urgent_ptr:  u16,
    options: Vec<TcpOption>
}

#[allow(unused_must_use)]
impl Tcp {
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.source);
        cursor.write_u16::<NetworkEndian>(self.destination);
        cursor.write_u32::<NetworkEndian>(self.sequence);
        cursor.write_u32::<NetworkEndian>(self.acknowledgement);
        cursor.write(&vec![self.data_offset << 4 | self.ns]);
        cursor.write(&vec![(self.cwr << 7) & 0b1000_0000 |
                           (self.ece << 6) & 0b0100_0000 |
                           (self.urg << 5) & 0b0010_0000 |
                           (self.ack << 4) & 0b0001_0000 |
                           (self.psh << 3) & 0b0000_1000 |
                           (self.rst << 2) & 0b0000_0100 |
                           (self.syn << 1) & 0b0000_0010 |
                           (self.fin << 0) & 0b0000_0001]);
        cursor.write_u16::<NetworkEndian>(self.window_size);
        cursor.write_u16::<NetworkEndian>(self.checksum);
        cursor.write_u16::<NetworkEndian>(self.urgent_ptr);
        let options_bin =
            self.options
            .iter()
            .fold(vec![], |acc, opt| [acc, opt.clone().as_bytes()].concat());
        cursor.write(&options_bin);
        let pad_len = (self.data_offset - 5) * 4 - options_bin.len() as u8;
        cursor.write(&(vec![0; pad_len as usize]));
        cursor.into_inner()
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Tcp> {
        do_parse!(
            bytes,
            source:          be_u16 >>
            destination:     be_u16 >>
            sequence:        be_u32 >>
            acknowledgement: be_u32 >>
            data_ofs_ns:     be_u8  >>
            flags_rest:      be_u8  >>
            window_size:     be_u16 >>
            checksum:        be_u16 >>
            urgent_ptr:      be_u16 >>
            options_bin:     take!((((data_ofs_ns >> 4) - 5) * 4) as usize) >>
                (
                    Tcp {
                        source: source,
                        destination: destination,
                        sequence: sequence,
                        acknowledgement: acknowledgement,
                        data_offset: data_ofs_ns >> 4,
                        ns: data_ofs_ns & 0b0000_0001,
                        cwr: (flags_rest >> 7) & 0b0000_0001,
                        ece: (flags_rest >> 6) & 0b0000_0001,
                        urg: (flags_rest >> 5) & 0b0000_0001,
                        ack: (flags_rest >> 4) & 0b0000_0001,
                        psh: (flags_rest >> 3) & 0b0000_0001,
                        rst: (flags_rest >> 2) & 0b0000_0001,
                        syn: (flags_rest >> 1) & 0b0000_0001,
                        fin: (flags_rest >> 0) & 0b0000_0001,
                        window_size: window_size,
                        checksum: checksum,
                        urgent_ptr: urgent_ptr,
                        options: Self::parse_options(options_bin)
                    }
                )
        )
    }

    // Private functions

    fn parse_options(bytes: &[u8]) -> Vec<TcpOption> {
        let mut acc = Vec::new();
        let mut b = bytes;

        loop {
            let (leftover, option) = TcpOption::from_bytes(b).unwrap();

            if option.number == 0 {
                acc.push(option);
                return acc
            }

            acc.push(option);
            b = leftover;
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct TcpOption {
    number: u8,
    length: Vec<u8>,
    data:   Vec<u8>
}

#[allow(unused_must_use)]
impl TcpOption {
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write(&vec![self.number]);
        cursor.write(&self.length);
        cursor.write(&self.data);
        cursor.into_inner()
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], TcpOption> {
        do_parse!(
            bytes,
            number: be_u8 >>
            data: call!(tcp_option_data, number) >>
                (
                    TcpOption {
                        number: number,
                        length: data.0,
                        data:   data.1
                    }
                )
        )
    }
}

fn tcp_option_data(bytes: &[u8], number: u8) -> IResult<&[u8], (Vec<u8>, Vec<u8>)> {
    match number {
        // End-of-Option list and No-Op
        0 | 1 => {
            Ok((bytes, (vec![], vec![])))
        },
        _ => {
            let (bytes1, length) = be_u8(bytes)?;
            let (bytes2, value) = take((length - 2) as usize)(bytes1)?;
            Ok((bytes2, (vec![length], value.to_vec())))

        }
    }
}

#[cfg(test)]
mod tests_tcp {
    use crate::tcp::{Tcp, TcpOption};

    #[test]
    fn parse() {
        let frame = &mut [
            0x00,0x50,0xd9,0xb8,0xde,0x0d,0x16,0x2b,
            0xf1,0x4b,0x09,0x0c,0xb0,0x12,0x11,0x04,
            0x8c,0x56,0x00,0x00,0x02,0x04,0x05,0xac,
            0x01,0x03,0x03,0x00,0x01,0x01,0x08,0x0a,
            0xbe,0x0f,0xac,0xec,0x00,0x40,0xa1,0x49,
            0x04,0x02,0x00,0x00
        ];

        let tcp = Tcp::from_bytes(frame).unwrap().1;
        assert_eq!(80, tcp.source);
        assert_eq!(55_736, tcp.destination);
        assert_eq!(3_725_399_595, tcp.sequence);
        assert_eq!(4_048_226_572, tcp.acknowledgement);
        assert_eq!(11, tcp.data_offset);
        assert_eq!(0, tcp.ns);
        assert_eq!(0, tcp.cwr);
        assert_eq!(0, tcp.ece);
        assert_eq!(0, tcp.urg);
        assert_eq!(1, tcp.ack);
        assert_eq!(0, tcp.psh);
        assert_eq!(0, tcp.rst);
        assert_eq!(1, tcp.syn);
        assert_eq!(0, tcp.fin);
        assert_eq!(4_356, tcp.window_size);
        assert_eq!(35_926, tcp.checksum);
        assert_eq!(0, tcp.urgent_ptr);
        assert_eq!(vec![
            // MSS
            TcpOption { number: 2, length: vec![4], data: vec![5, 172] },
            // NoOp
            TcpOption { number: 1, length: vec![], data: vec![] },
            // Window Scale
            TcpOption { number: 3, length: vec![3], data: vec![0] },
            // NoOp
            TcpOption { number: 1, length: vec![], data: vec![] },
            // NoOp
            TcpOption { number: 1, length: vec![], data: vec![] },
            // TSOPT(TimeStamp)
            TcpOption { number: 8, length: vec![10], data: vec![190, 15, 172, 236, 0, 64, 161, 73] },
            // SACK
            TcpOption { number: 4, length: vec![2], data: vec![] },
            // End of Options
            TcpOption { number: 0, length: vec![], data: vec![] }
        ], tcp.options);
    }
}
