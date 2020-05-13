#[derive(Debug, PartialEq)]
pub struct Gre {
    pub has_csum:     u8,
    pub has_key:      u8,
    pub has_sequence: u8,
    pub version:             u8,
    pub protocol:            u16,
    // optional
    pub checksum:            u16,
    pub key:                 u32,
    pub sequence:            u32
}
