use byteorder::{NetworkEndian, WriteBytesExt};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{call, do_parse, IResult};
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq)]
pub struct Gre {
    pub has_csum:     bool,
    pub has_key:      bool,
    pub has_sequence: bool,
    pub version:      u8,
    pub protocol:     u16,
    // optional
    pub checksum: u16,
    pub key:      u32,
    pub sequence: u32
}

impl Default for Gre {
    fn default() -> Gre {
        Gre {
            has_csum:     false,
            has_key:      false,
            has_sequence: false,
            version:      u8::default(),
            protocol:     u16::default(),
            checksum:     u16::default(),
            key:          u32::default(),
            sequence:     u32::default()
        }
    }
}

#[allow(unused_must_use)]
impl Gre {
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        let has_csum = if self.has_csum { 0x80 } else { 0x00 };
        let has_key  = if self.has_key { 0x20 } else { 0x00 };
        let has_seq  = if self.has_sequence { 0x10 } else { 0x00 };
        let version  = self.version;
        cursor.write(&vec![has_csum | has_key | has_seq, version]);
        cursor.write_u16::<NetworkEndian>(self.protocol);
        if self.has_csum {
            cursor.write_u16::<NetworkEndian>(self.checksum);
            cursor.write_u16::<NetworkEndian>(0);
        }
        if self.has_key { cursor.write_u32::<NetworkEndian>(self.key); }
        if self.has_sequence { cursor.write_u32::<NetworkEndian>(self.sequence); }
        cursor.into_inner()
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Gre> {
        do_parse!(
            bytes,
            flags:     be_u8  >>
            version:   be_u8  >>
            protocol:  be_u16 >>
            options:   call!(Self::parse_options, flags) >>
                (
                    Gre {
                        has_csum:      (flags >> 7) != 0,
                        has_key:       (flags >> 5) != 0,
                        has_sequence:  (flags >> 4) != 0,
                        version:       version & 0x07,
                        protocol:      protocol,
                        checksum:      options.0,
                        key:           options.1,
                        sequence:      options.2,
                    }
                )
        )
    }

    // private functions

    fn parse_options(bytes0: &[u8], flags: u8) -> IResult<&[u8], (u16, u32, u32)> {
        let (bytes1, csum) = if (flags & 0x80) != 0 { be_u16(bytes0)? } else { (bytes0, 0) };
        let (bytes2, _res) = if (flags & 0x80) != 0 { be_u16(bytes1)? } else { (bytes1, 0) };
        let (bytes3, key)  = if (flags & 0x20) != 0 { be_u32(bytes2)? } else { (bytes2, 0) };
        let (bytes4, seq)  = if (flags & 0x10) != 0 { be_u32(bytes3)? } else { (bytes3, 0) };
        Ok((bytes4, (csum, key, seq)))
    }
}

#[cfg(test)]
mod tests_gre {
    use crate::gre::Gre;

    #[test]
    fn parse() {
        let frame = &mut [
            0x30,0x00,0x08,0x00,0x00,0x00,0x30,0x39,
            0x00,0x00,0x00,0x01,0x45,0x00,0x00,0x14,
            0x00,0x00,0x00,0x00,0x40,0x06,0x00,0x00,
            0x7f,0x00,0x00,0x01,0x7f,0x00,0x00,0x01
        ];

        let mut gre0 = Gre::from_bytes(frame).unwrap().1;
        gre0.has_csum = true;
        gre0.checksum = 128;
        let gre1 = Gre::from_bytes(&gre0.as_bytes()).unwrap().1;
        assert_eq!(Gre {
            has_csum:     true,
            has_key:      true,
            has_sequence: true,
            version:         0,
            protocol:   0x0800,
            checksum:     0x80,
            key:         12345,
            sequence:        1
        }, gre1);
    }
}
