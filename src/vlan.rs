use byteorder::{NetworkEndian, WriteBytesExt};
use nom::number::complete::be_u16;
use nom::{do_parse, IResult};
use std::fmt;
use std::io::Cursor;

#[derive(Debug, PartialEq)]
pub struct Dot1Q {
    tpid: u16,
    tci:  u16
}

impl Default for Dot1Q {
    fn default() -> Dot1Q {
        Dot1Q {
            tpid: u16::default(),
            tci:  u16::default()
        }
    }
}

impl fmt::Display for Dot1Q {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Dot1Q(\
             tpid: 0x{:x}, \
             pcp: {}, \
             vid: {}\
             )",
            self.tpid,
            self.tci >> 13,
            self.tci & 0x1fff
        )
    }
}

#[allow(unused_must_use)]
impl Dot1Q {
    pub fn new() -> Dot1Q { Dot1Q::default() }

    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write_u16::<NetworkEndian>(self.tci);
        cursor.write_u16::<NetworkEndian>(self.tpid);
        cursor.into_inner()
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Dot1Q> {
        do_parse!(
            bytes,
            tci:  be_u16 >>
            tpid: be_u16 >>
                (
                    Dot1Q {
                        tci:  tci,
                        tpid: tpid
                    }
                )
        )
    }
}

#[cfg(test)]
mod tests_dot1q {
    use crate::vlan::Dot1Q;

    #[test]
    fn parse() {
        let frame = &mut [
            0x00,0x64,
            0x81,0x00,0x00,0xc8,0x08,0x06,0x00,0x01,
            0x08,0x00,0x06,0x04,0x00,0x01,0xca,0x03,
            0x0d,0xb4,0x00,0x1c,0xc0,0xa8,0x02,0xc8,
            0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,
            0x02,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ];

        let vlan = Dot1Q::from_bytes(frame).unwrap().1;
        let vlan = Dot1Q::from_bytes(&vlan.as_bytes()).unwrap().1;
        assert_eq!(0x8100, vlan.tpid);
        assert_eq!(100, vlan.tci & 0x1fff); // vlan vid + cfi bit
        assert_eq!(0, vlan.tci >> 13); // vlan pcp
    }
}
