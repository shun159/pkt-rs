use byteorder::{NetworkEndian, WriteBytesExt};
use nom::number::complete::{be_u8, be_u16, be_u24};
use nom::{do_parse, IResult};
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq)]
pub struct Vxlan {
    pub has_vni:         bool,
    pub vni:             u32,
    pub has_gbp_ext:     bool,
    pub gbp_applied:     bool,
    pub dont_learn:      bool,
    pub group_policy_id: u16
}

impl Default for Vxlan {
    fn default() -> Vxlan {
        Vxlan {
            has_vni:         false,
            vni:             u32::default(),
            has_gbp_ext:     false,
            gbp_applied:     false,
            dont_learn:      false,
            group_policy_id: u16::default()
        }
    }
}

#[allow(unused_must_use)]
impl Vxlan {
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        let has_gbp_ext = if self.has_gbp_ext { 0x8000 } else { 0x0000 };
        let has_vni     = if self.has_vni { 0x0800 } else { 0x0000 };
        let dont_learn  = if self.dont_learn { 0x0040 } else { 0x0000 };
        let gbp_applied = if self.gbp_applied { 0x0008 } else { 0x0000 };
        cursor.write_u16::<NetworkEndian>(has_gbp_ext | has_vni | dont_learn | gbp_applied);
        cursor.write_u16::<NetworkEndian>(self.group_policy_id);
        cursor.write_u24::<NetworkEndian>(self.vni);
        cursor.write(&vec![0x00]);
        cursor.into_inner()
    }

    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], Vxlan> {
        do_parse!(
            bytes,
            flags:    be_u16 >>
            group_id: be_u16 >>
            vni:      be_u24 >>
            _res:     be_u8  >>
                (
                    Vxlan {
                        has_gbp_ext: flags & 0x8000 > 0,
                        has_vni:     flags & 0x0800 > 0,
                        dont_learn:  flags & 0x0040 > 0,
                        gbp_applied: flags & 0x0008 > 0,
                        vni: vni,
                        group_policy_id: group_id
                    }
                )
        )
    }
}

#[cfg(test)]
mod test_vxlan {
    use crate::vxlan::Vxlan;

    #[test]
    fn parse() {
        let frame = &mut [
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00,
            0xba, 0x09, 0x2b, 0x6e, 0xf8, 0xbe, 0x4a, 0x7f,
            0x01, 0x3b, 0xa2, 0x71, 0x08, 0x06, 0x00, 0x01,
            0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x4a, 0x7f,
            0x01, 0x3b, 0xa2, 0x71, 0x0a, 0x00, 0x00, 0x02,
            0xba, 0x09, 0x2b, 0x6e, 0xf8, 0xbe, 0x0a, 0x00,
            0x00, 0x01
        ];

        let mut vxlan0 = Vxlan::from_bytes(frame).unwrap();

        // mutation
        vxlan0.1.has_gbp_ext = true;
        vxlan0.1.group_policy_id = 128;

        // write and parse
        let vxlan1 = Vxlan::from_bytes(&vxlan0.1.as_bytes()).unwrap().1;
        assert_eq!(Vxlan {
            has_gbp_ext:     true,
            has_vni:         true,
            dont_learn:      false,
            gbp_applied:     false,
            vni:             123,
            group_policy_id: 128
        }, vxlan1);
    }
}
