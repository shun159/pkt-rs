use byteorder::{NetworkEndian, WriteBytesExt};
use std::net::Ipv4Addr;
use eui48::MacAddress;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16};
use nom::{do_parse, IResult};
use std::fmt;
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct Arp {
    pub hardware_type:   u16,
    pub protocol_type:   u16,
    pub hardware_length: u8,
    pub protocol_length: u8,
    pub operation:       u16,
    pub sha:             MacAddress,
    pub spa:             Ipv4Addr,
    pub tha:             MacAddress,
    pub tpa:             Ipv4Addr
}

impl Default for Arp {
    fn default() -> Arp {
        Arp {
            hardware_type:   1,
            protocol_type:   0x0800,
            hardware_length: 6,
            protocol_length: 4,
            operation:       1,
            sha: MacAddress::nil(),
            spa: Ipv4Addr::new(0, 0, 0, 0),
            tha: MacAddress::nil(),
            tpa: Ipv4Addr::new(0, 0, 0, 0)
        }
    }
}

impl fmt::Display for Arp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Arp(\
             sha: \"{}\", \
             spa: \"{}\", \
             tha: \"{}\", \
             tpa: \"{}\", \
             )",
            self.sha.to_hex_string(),
            self.spa,
            self.tha.to_hex_string(),
            self.tpa,
        )
    }
}

#[allow(unused_must_use)]
impl Arp {
    // Instantiate a new ARP header
    pub fn new() -> Arp { Arp::default() }

    // Encode the ARP frame into a byte slice
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.hardware_type);
        cursor.write_u16::<NetworkEndian>(self.protocol_type);
        cursor.write(&vec![self.hardware_length]);
        cursor.write(&vec![self.protocol_length]);
        cursor.write_u16::<NetworkEndian>(self.operation);
        cursor.write(self.sha.as_bytes());
        cursor.write(&self.spa.octets().to_vec());
        cursor.write(self.tha.as_bytes());
        cursor.write(&self.tpa.octets().to_vec());
        cursor.into_inner()
    }

    // Parse a byte slice
    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Arp> {
        do_parse!(
            bytes,
            hardware_type: be_u16 >>
            protocol_type: be_u16 >>
            hardware_length: be_u8 >>
            protocol_length: be_u8 >>
            operation: be_u16 >>
            sha: parse_macaddr >>
            spa: parse_ip4addr >>
            tha: parse_macaddr >>
            tpa: parse_ip4addr >>
                (
                    Arp {
                        hardware_type: hardware_type,
                        protocol_type: protocol_type,
                        hardware_length: hardware_length,
                        protocol_length: protocol_length,
                        operation: operation,
                        sha: sha,
                        spa: spa,
                        tha: tha,
                        tpa: tpa
                    }
                )
        )
    }
}

// private functions

fn parse_macaddr(bytes: &[u8]) -> IResult<&[u8], MacAddress> {
    let (bytes1, val) = take(6usize)(bytes)?;
    let macaddr = MacAddress::from_bytes(val).unwrap();
    Ok((bytes1, macaddr))
}

fn parse_ip4addr(bytes: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    let (bytes1, value) = take(4usize)(bytes)?;
    let ip4addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
    Ok((bytes1, ip4addr))
}

#[cfg(test)]
mod tests_arp {
    use eui48::MacAddress;
    use crate::arp::Arp;
    use std::str::FromStr;
    use std::net::Ipv4Addr;

    #[test]
    fn parse() {
        let frame = &mut [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x16,
            0xb6, 0xb5, 0x3e, 0xc6, 0x08, 0x06, 0x00, 0x01,
            0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x16,
            0xb6, 0xb5, 0x3e, 0xc6, 0xc0, 0xa8, 0xd5, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8,
            0xd5, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x81, 0x01, 0x0a, 0x68
        ];

        let arp1 = Arp::from_bytes(frame).unwrap().1;
        let arp2 = Arp::from_bytes(&arp1.as_bytes()).unwrap().1;
        assert_eq!(0xffff, arp2.hardware_type);
        assert_eq!(0xffff, arp2.protocol_type);
        assert_eq!(0xff, arp2.hardware_length);
        assert_eq!(0xff, arp2.protocol_length);
        assert_eq!(22, arp2.operation);
        assert_eq!(MacAddress::from_str("b6:b5:3e:c6:08:06").unwrap(), arp2.sha);
        assert_eq!(Ipv4Addr::new(0, 1, 8, 0), arp2.spa);
        assert_eq!(MacAddress::from_str("06:04:00:01:00:16").unwrap(), arp2.tha);
        assert_eq!(Ipv4Addr::new(182, 181, 62, 198), arp2.tpa);
    }
}
