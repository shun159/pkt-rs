use byteorder::{NetworkEndian, WriteBytesExt};
use nom::number::complete::be_u16;
use nom::{do_parse, IResult};
use std::fmt;
use std::io::Cursor;

#[derive(Debug, PartialEq)]
pub struct Udp {
    pub source:      u16,
    pub destination: u16,
    pub length:      u16,
    pub checksum:    u16
}

impl Default for Udp {
    fn default() -> Udp {
        Udp {
            source:      0,
            destination: 0,
            length:      8,
            checksum:    0
        }
    }
}

impl fmt::Display for Udp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UDP(\
             source: {}, \
             destination: {}, \
             length: {}\
             )",
            self.source,
            self.destination,
            self.length
        )
    }
}

#[allow(unused_must_use)]
impl Udp {
    // Instantiate a new UDP header
    pub fn new() -> Udp { Udp::default() }

    // Encode the UDP frame into a byte slice
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.source);
        cursor.write_u16::<NetworkEndian>(self.destination);
        cursor.write_u16::<NetworkEndian>(self.length);
        cursor.write_u16::<NetworkEndian>(self.checksum);
        cursor.into_inner()
    }

    // Parse a byte slice
    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Udp> {
        do_parse!(
            bytes,
            source:      be_u16 >>
            destination: be_u16 >>
            length:      be_u16 >>
            checksum:    be_u16 >>
                (
                    Udp {
                        source: source,
                        destination: destination,
                        length: length,
                        checksum: checksum
                    }
                )
        )
    }
}

#[cfg(test)]
mod tests_udp {
    use crate::udp::Udp;

    #[test]
    fn parse() {
        let frame = &mut [
            0x82,0x75,0x7a,0x69,0x00,0x0e,0xa6,0x0e,
            0x74,0x65,0x73,0x65,0x74,0x0a
        ];

        let udp1 = Udp::from_bytes(frame).unwrap().1;
        let udp2 = Udp::from_bytes(&udp1.as_bytes()).unwrap().1;
        assert_eq!(33397, udp2.source);
        assert_eq!(31337, udp2.destination);
        assert_eq!(14, udp2.length);
        assert_eq!(42510, udp2.checksum);
        assert_eq!(
            "UDP(\
             source: 33397, \
             destination: \
             31337, \
             length: 14\
             )",
            format!("{}", udp2)
        );
    }
}
