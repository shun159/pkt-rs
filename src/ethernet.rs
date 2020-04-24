use byteorder::{NetworkEndian, WriteBytesExt};
use eui48::MacAddress;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use nom::{do_parse, IResult};
use std::fmt;
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq)]
#[repr(C)]
pub struct Ethernet {
    destination: MacAddress,
    source:      MacAddress,
    eth_type:    u16
}

impl Default for Ethernet {
    fn default() -> Ethernet {
        Ethernet {
            destination: MacAddress::nil(),
            source:      MacAddress::nil(),
            eth_type:    0
        }
    }
}

impl fmt::Display for Ethernet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ethernet(dst: \"{}\", src: \"{}\", type: {:x})",
            self.destination.to_hex_string(),
            self.source.to_hex_string(),
            self.eth_type
        )
    }
}

#[allow(unused_must_use)]
impl Ethernet {
    // Instantiate a new Ethernet Header
    pub fn new() -> Ethernet { Ethernet::default() }

    // Encode the Ethernet frame into a byte slice
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write(self.destination.as_bytes());
        cursor.write(self.source.as_bytes());
        cursor.write_u16::<NetworkEndian>(self.eth_type);
        cursor.into_inner()
    }

    // Parse a byte slice
    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Ethernet> {
        do_parse!(
            bytes,
            destination: parse_macaddr >>
            source:      parse_macaddr >>
            eth_type:    be_u16        >>
                (
                    Ethernet {
                        destination: destination,
                        source:      source,
                        eth_type:    eth_type
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

#[cfg(test)]
mod tests_ethernet {
    use crate::ethernet::Ethernet;

    #[test]
    fn to_string() {
        let frame = &mut [
            0x00, 0x50, 0xd9, 0xb8, 0xde, 0x0d, 0x16, 0x2b,
            0xf1, 0x4b, 0x09, 0x0c, 0x08, 0x00, 0x11, 0x04,
            0x8c, 0x56, 0x00, 0x00, 0x02, 0x04, 0x05, 0xac,
            0x01, 0x03, 0x03, 0x00, 0x01, 0x01, 0x08, 0x0a,
            0xbe, 0x0f, 0xac, 0xec, 0x00, 0x40, 0xa1, 0x49,
            0x04, 0x02, 0x00, 0x00
        ];

        let ether = Ethernet::from_bytes(frame).unwrap().1;
        let ether_str = format!("{}", ether);
        assert_eq!(
            "Ethernet(\
             dst: \"00:50:d9:b8:de:0d\", \
             src: \"16:2b:f1:4b:09:0c\", \
             type: 800\
             )",
            ether_str
        );
    }

    #[test]
    fn parse() {
        let frame = &mut [
            0xff,0xff,0xff,0xff,0xff,0xff,0x24,0xdb,
            0xac,0x41,0xe5,0x5b,0x08,0x00,0x45,0x00,
            0x01,0x48,0x00,0x00,0x00,0x00,0x80,0x11,
            0x39,0xa6,0x00,0x00,0x00,0x00,0xff,0xff,
            0xff,0xff,0x00,0x44,0x00,0x43,0x01,0x34,
            0x88,0x14,0x01,0x01,0x06,0x00,0xde,0xad,
            0xbe,0xef,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x24,0xdb,
            0xac,0x41,0xe5,0x5b,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x63,0x82,
            0x53,0x63,0x35,0x01,0x01,0x3d,0x07,0x01,
            0x24,0xdb,0xac,0x41,0xe5,0x5b,0x32,0x04,
            0x00,0x00,0x00,0x00,0x37,0x04,0x01,0x03,
            0x06,0x2a,0xff,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00
        ];

        let ethernet1 = Ethernet::from_bytes(frame).unwrap().1;
        let eth_type = ethernet1.eth_type;
        let ethernet2 = Ethernet::from_bytes(&ethernet1.as_bytes()).unwrap().1;
        assert_eq!(eth_type, ethernet2.eth_type);
    }
}
