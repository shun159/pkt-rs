extern crate eui48;
extern crate libc;
extern crate nom;

pub mod arp;
pub mod ethernet;
pub mod gre;
pub mod ipv4;
pub mod icmpv4;
pub mod udp;
pub mod tcp;
pub mod vlan;

use arp::Arp;
use ethernet::Ethernet;
use gre::Gre;
use icmpv4::Icmpv4;
use ipv4::IPv4;
use udp::Udp;
use tcp::Tcp;
use vlan::Dot1Q;

use std::result::Result;

#[derive(Debug, PartialEq)]
pub enum Packet {
    ETHER(Ethernet),
    ARP(Arp),
    VLAN(Dot1Q),
    IPv4(IPv4),
    ICMP4(Icmpv4),
    UDP(Udp),
    TCP(Tcp),
    Payload(Vec<u8>)
}

impl Packet {
    pub fn parse<'a>(bytes: &'a [u8]) -> Vec<Packet> {
        let mut headers: Vec<Packet> = Vec::new();
        let mut leftover: &[u8];
        match Self::parse_eth(bytes) {
            Err(leftover) =>
                headers.push(Packet::Payload(leftover.to_vec())),
            Ok((b, ethernet)) => {
                leftover = b;
                headers.push(ethernet);
                while leftover != &[] {
                    leftover = Self::parse_next(leftover, &mut headers);
                }
            }
        }

        return headers
    }

    fn parse_next<'a>(bytes: &'a [u8], pkt: &mut Vec<Packet>) -> &'a [u8] {
        let result: Result<(&[u8], Packet), &[u8]> = match pkt.last().unwrap() {
            // ETH_P_ARP
            Packet::ETHER(Ethernet{ eth_type: 0x0806, .. }) |
            Packet::VLAN(Dot1Q{ tpid: 0x0806, .. }) =>
                Self::parse_arp(bytes),
            // ETH_P_802_1Q
            Packet::ETHER(Ethernet{ eth_type: 0x8100, .. }) |
            Packet::VLAN(Dot1Q{ tpid: 0x8100, .. }) =>
                Self::parse_vlan(bytes),
            // ETH_P_IP
            Packet::ETHER(Ethernet{ eth_type: 0x0800, .. }) |
            Packet::VLAN(Dot1Q{ tpid: 0x0800, .. }) =>
                Self::parse_ip4(bytes),
            // IPPROTO_ICMP
            Packet::IPv4(IPv4{ protocol: 1, .. }) =>
                Self::parse_icmp4(bytes),
            // IPPROTO_TCP
            Packet::IPv4(IPv4{ protocol: 6, .. }) =>
                Self::parse_tcp(bytes),
            // IPPROTO_TCP
            Packet::IPv4(IPv4{ protocol: 17, .. }) =>
                Self::parse_udp(bytes),
            // Other
            _other => {
                let packet = Packet::Payload(bytes.to_vec());
                Result::Ok((&[], packet))
            }
        };

        match result {
            Err(bytes) => {
                pkt.push(Packet::Payload(bytes.to_vec()));
                &[]
            },

            Ok((leftover, header)) => {
                pkt.push(header);
                leftover
            }
        }
    }

    // Parse Ether frame header
    fn parse_eth(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match Ethernet::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, ethernet)) => {
                let pkt = Packet::ETHER(ethernet);
                return Result::Ok((leftover, pkt))
            }
        }
    }

    // Parse ARP Header
    fn parse_arp(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match Arp::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, arp)) => {
                let pkt = Packet::ARP(arp);
                return Result::Ok((leftover, pkt))
            }
        }
    }

    // Parse 802.1q vlan tag header
    fn parse_vlan(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match Dot1Q::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, vlan)) => {
                let pkt = Packet::VLAN(vlan);
                return Result::Ok((leftover, pkt))
            }
        }
    }

    // Parse IPv4 Header
    fn parse_ip4(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match IPv4::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, ipv4)) => {
                let pkt = Packet::IPv4(ipv4);
                return Result::Ok((leftover, pkt))
            }
        }
    }

    // Parse ICMP4 Header
    fn parse_icmp4(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match Icmpv4::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, icmpv4)) => {
                let pkt = Packet::ICMP4(icmpv4);
                return Result::Ok((leftover, pkt))
            }
        }
    }

    // Parse TCP Header
    fn parse_tcp(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match Tcp::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, tcp)) => {
                let pkt = Packet::TCP(tcp);
                return Result::Ok((leftover, pkt))
            }
        }
    }

    // Parse UDP Header
    fn parse_udp(bytes: &[u8]) -> Result<(&[u8], Packet), &[u8]> {
        match Udp::from_bytes(bytes) {
            Err(_e) =>
                return Result::Err(bytes),
            Ok((leftover, udp)) => {
                let pkt = Packet::UDP(udp);
                return Result::Ok((leftover, pkt))
            }
        }
    }
}

#[cfg(test)]
mod tests_pkt {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use eui48::MacAddress;
    use crate::ethernet::*;
    use crate::arp::*;
    use crate::vlan::*;
    use crate::Packet;
    use crate::Packet::{
        ETHER,
        VLAN,
        ARP,
        Payload
    };

    #[test]
    fn parse_arp() {
        let frame = [
            0xff,0xff,0xff,0xff,0xff,0xff,0xca,0x03,
            0x0d,0xb4,0x00,0x1c,0x81,0x00,0x00,0x64,
            0x81,0x00,0x00,0xc8,0x08,0x06,0x00,0x01,
            0x08,0x00,0x06,0x04,0x00,0x01,0xca,0x03,
            0x0d,0xb4,0x00,0x1c,0xc0,0xa8,0x02,0xc8,
            0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xa8,
            0x02,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ];

        let pkt = Packet::parse(&frame);
        assert_eq!(
            vec![
                ETHER(Ethernet {
                    destination: MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
                    source: MacAddress::from_str("ca:03:0d:b4:00:1c").unwrap(),
                    eth_type: 33024
                }),
                VLAN(Dot1Q {
                    tpid: 33024,
                    tci: 100
                }),
                VLAN(Dot1Q {
                    tpid: 2054,
                    tci: 200
                }),
                ARP(Arp {
                    hardware_type: 1,
                    protocol_type: 2048,
                    hardware_length: 6,
                    protocol_length: 4,
                    operation: 1,
                    sha: MacAddress::from_str("ca:03:0d:b4:00:1c").unwrap(),
                    spa: Ipv4Addr::new(192,168,2,200),
                    tha: MacAddress::from_str("00:00:00:00:00:00").unwrap(),
                    tpa: Ipv4Addr::new(192,168,2,254)
                }
                ),
                Payload(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            ],
            pkt
        )
    }
}
