use byteorder::{NetworkEndian, WriteBytesExt};
use nom::number::complete::{be_u8, be_u16};
use nom::combinator::rest;
use nom::{do_parse, IResult};
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq)]
pub struct Icmpv4 {
    pub icmp_code: u8,
    pub icmp_type: u8,
    pub checksum:  u16,
    pub payload:   Vec<u8>
}

impl Default for Icmpv4 {
    fn default() -> Icmpv4 {
        Icmpv4 {
            icmp_code: 0,
            icmp_type: 0,
            checksum:  0,
            payload:   Vec::new()
        }
    }
}

#[allow(unused_must_use)]
impl Icmpv4 {
    pub fn new() -> Icmpv4 { Icmpv4::default() }

    pub fn calculate_icmp_checksum(&self) -> u16 {
        let payload: Vec<u16> = self.payload
            .chunks_exact(2)
            .into_iter()
            .map(|i| u16::from_ne_bytes([i[1], i[0]]))
            .collect();

        let fields: Vec<u16> = [vec![
            (self.icmp_code as u16) << 8 |
            self.icmp_type as u16,
        ], payload].concat();

        let sum = fields.iter().fold(0u32, |acc, &i| acc + (i as u32));
        !(((sum & 0xffff) + (sum >> 16)) & 0xffff) as u16
    }

    pub fn as_bytes(self)-> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write(&vec![self.icmp_code]);
        cursor.write(&vec![self.icmp_type]);
        cursor.write_u16::<NetworkEndian>(self.checksum);
        cursor.write(&self.payload);
        cursor.into_inner()
    }

    // Parse a byte slice into an ICMP4 Any types
    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Icmpv4> {
        do_parse!(
            bytes,
            icmp_code: be_u8 >>
            icmp_type: be_u8 >>
            checksum:  be_u16 >>
            payload:   rest >>
                (
                    Icmpv4 {
                        icmp_code: icmp_code,
                        icmp_type: icmp_type,
                        checksum:  checksum,
                        payload:   payload.to_vec()
                    }
                )
        )
    }
}

#[cfg(test)]
mod tests_icmp4 {
    use crate::icmpv4::Icmpv4;

    #[test]
    fn parse() {
        let frame = &mut [
            0x00,0x00,0x93,0xd6,0x05,0x41,0x00,0x01,
            0x71,0xf1,0x66,0x52,0x00,0x00,0x00,0x00,
            0xc6,0xd0,0x09,0x00,0x00,0x00,0x00,0x00,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
            0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
            0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
            0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
        ];

        let icmp4 = Icmpv4::from_bytes(frame).unwrap().1;
        let icmp4 = Icmpv4::from_bytes(&icmp4.as_bytes()).unwrap().1;
        assert_eq!(icmp4.icmp_code, 0);
        assert_eq!(icmp4.icmp_type, 0);
        assert_eq!(icmp4.checksum,  37_846);
        assert_eq!(37_846, icmp4.calculate_icmp_checksum());
    }
}
