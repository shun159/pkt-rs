use byteorder::{NetworkEndian, WriteBytesExt};
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16};
use nom::{do_parse, take, IResult};
use std::fmt;
use std::net::Ipv4Addr;
use std::io::{Cursor, Write};

#[derive(Debug, PartialEq)]
pub struct IPv4 {
    version_ihl:     u8,
    tos:             u8,
    total_length:    u16,
    identifier:      u16,
    fragment_offset: u16,
    ttl:             u8,
    protocol:        u8,
    checksum:        u16,
    source:          Ipv4Addr,
    destination:     Ipv4Addr,
    options:         Vec<u8>
}

impl Default for IPv4 {
    fn default() -> IPv4 {
        IPv4 {
            version_ihl: 4 << 4 | 5,
            tos:         0,
            total_length:   20,
            identifier:  0,
            fragment_offset: 0,
            ttl:         8,
            protocol:    0,
            checksum:    0,
            source:      Ipv4Addr::new(0, 0, 0, 0),
            destination: Ipv4Addr::new(0, 0, 0, 0),
            options:     Vec::new()
        }
    }
}

impl fmt::Display for IPv4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tot = self.total_length;
        let ttl = self.ttl;
        let prt = self.protocol;
        let src = self.source;
        let dst = self.destination;

        write!(
            f,
            "IPv4(\
             source: \"{}\", \
             destination: \"{}\", \
             tot_len: {}, \
             ttl: {}, \
             proto: {}\
             )",
            src,
            dst,
            tot,
            ttl,
            prt
        )
    }
}

#[allow(unused_must_use)]
impl IPv4 {
    // Instantiate IPv4 header
    pub fn new() -> IPv4 { IPv4::default() }

    // Calcurate ipv4 checksum
    pub fn calculate_ip_checksum(&self) -> u16 {
        let fields: Vec<u16> = vec![
            (self.version_ihl as u16) << 8 |
            self.tos as u16,
            self.total_length,
            self.identifier,
            self.fragment_offset,
            (self.ttl as u16) << 8 |
            self.protocol as u16,
            (u32::from(self.source)      >> 16)    as u16,
            (u32::from(self.source)      & 0xffff) as u16,
            (u32::from(self.destination) >> 16)    as u16,
            (u32::from(self.destination) & 0xffff) as u16
        ];

        let mut tmp_sum = fields.iter().fold(0u32, |acc, &i| acc + (i as u32));
        while tmp_sum > 0xffff { tmp_sum = (tmp_sum >> 16) + (tmp_sum & 0xffff) }
        !tmp_sum as u16
    }

    // Encode the IPv4 Header into a vec of u8
    pub fn as_bytes(self) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut cursor = Cursor::new(buf);
        cursor.write(&vec![self.version_ihl]);
        cursor.write(&vec![self.tos]);
        cursor.write_u16::<NetworkEndian>(self.total_length);
        cursor.write_u16::<NetworkEndian>(self.identifier);
        cursor.write_u16::<NetworkEndian>(self.fragment_offset);
        cursor.write(&vec![self.ttl]);
        cursor.write(&vec![self.protocol]);
        cursor.write_u16::<NetworkEndian>(self.checksum);
        cursor.write(&self.source.octets().to_vec());
        cursor.write(&self.destination.octets().to_vec());
        cursor.write(&self.options);
        cursor.into_inner()
    }

    // Parse a byte slice into an IPv4 header
    pub fn from_bytes(bytes: &[u8]) -> IResult<&[u8], IPv4> {
        do_parse!(
            bytes,
            version_ihl:     be_u8 >>
            tos:             be_u8 >>
            total_length:    be_u16 >>
            identifier:      be_u16 >>
            fragment_offset: be_u16 >>
            ttl:             be_u8 >>
            protocol:        be_u8 >>
            checksum:        be_u16 >>
            source:          parse_ip4addr >>
            destination:     parse_ip4addr >>
            options:         take!(((version_ihl & 0x0f) * 4 - 20) as usize) >>
                (
                    IPv4 {
                        version_ihl: version_ihl,
                        tos: tos,
                        total_length: total_length,
                        identifier: identifier,
                        fragment_offset: fragment_offset,
                        ttl: ttl,
                        protocol: protocol,
                        checksum: checksum,
                        source: source,
                        destination: destination,
                        options: options.to_vec()
                    }
                )
        )
    }
}

// private functions

fn parse_ip4addr(bytes: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    let (bytes1, value) = take(4usize)(bytes)?;
    let ip4addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
    Ok((bytes1, ip4addr))
}

#[cfg(test)]
mod tests_ipv4{
    use crate::ipv4::IPv4;

    #[test]
    fn parse() {
        let frame = &mut [
            0x45,0x00,0x01,0x48,0x00,0x00,0x00,0x00,
            0x80,0x11,0x39,0xa6,0x00,0x00,0x00,0x00,
            0xff,0xff,0xff,0xff,0x00,0x44,0x00,0x43,
            0x01,0x34,0x88,0x14,0x01,0x01,0x06,0x00,
            0xde,0xad,0xbe,0xef,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x24,0xdb,0xac,0x41,0xe5,0x5b,0x00,0x00,
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
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x63,0x82,0x53,0x63,0x35,0x01,0x01,0x3d,
            0x07,0x01,0x24,0xdb,0xac,0x41,0xe5,0x5b,
            0x32,0x04,0x00,0x00,0x00,0x00,0x37,0x04,
            0x01,0x03,0x06,0x2a,0xff,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ];

        let ipv4 = IPv4::from_bytes(frame).unwrap().1;
        let ipv4_csum = ipv4.checksum;
        let ipv4_totlen = ipv4.total_length;

        assert_eq!(ipv4_csum, ipv4.calculate_ip_checksum());

        let ipv4_b = ipv4.as_bytes();
        let ipv4_2 = IPv4::from_bytes(&ipv4_b).unwrap().1;

        assert_eq!(ipv4_csum, ipv4_2.checksum);
        assert_eq!(328, ipv4_totlen);
    }
}
