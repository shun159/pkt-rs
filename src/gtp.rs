#[derive(Debug, PartialEq)]
pub struct GtpExtHeader {
    pub ext_type: u8,
    pub content:  Vec<u8>
}

#[derive(Debug, PartialEq)]
pub struct Gtp {
    pub version:       u8,
    pub protocol_type: u8,
    pub has_ext_header:      bool,
    pub has_sequence_number: bool,
    pub has_npdu:            bool,
    pub message_type:    u8,
    pub message_length:  u16,
    pub teid:            u32,
    pub sequence_number: u16,
    pub npdu:            u8,
    pub ext_header:      Vec<GtpExtHeader>
}

impl Default for Gtp {
    fn default() -> Gtp {
        Gtp {
            version:             0,
            protocol_type:       0,
            has_ext_header:      false,
            has_sequence_number: false,
            has_npdu:            false,
            message_type:        0,
            message_length:      0,
            teid:                0,
            sequence_number:     0,
            npdu:                0,
            ext_header:          Vec::new()
        }
    }
}
