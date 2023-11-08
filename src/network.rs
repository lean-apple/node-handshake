use byteorder::{LittleEndian, WriteBytesExt};
use std::net::SocketAddr;

/// The different Bitcoin networks
#[derive(Debug, Clone, Copy)]
pub enum BitcoinNetwork {
    Mainnet,
    Regtest,
    Testnet3,
}

impl BitcoinNetwork {
    // Returns the magic value for every network
    pub fn magic(&self) -> [u8; 4] {
        match *self {
            BitcoinNetwork::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            BitcoinNetwork::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
            BitcoinNetwork::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
        }
    }
}

/// Helper to serialize IP address either V4 or V6 address
pub fn serialize_socket_add(payload: &mut Vec<u8>, services: u64, add: &SocketAddr) {
    payload
        .write_u64::<LittleEndian>(services)
        .expect("Failed to add services to the payload");
    match add {
        SocketAddr::V4(add_v4) => {
            // Serialize the IPv4 address in IPv6-mapped format ::ffff:0:0/96 prefix
            payload.extend(&[0; 10]); // First 10 bytes are zeros
            payload.extend(&[0xff, 0xff]); // Next 2 bytes are 0xff representing IPv4-mapping
            payload.extend_from_slice(&add_v4.ip().octets()); // IPv4 address
        }
        SocketAddr::V6(add_v6) => {
            // Serialize the IPv6 address directly
            for &segment in &add_v6.ip().segments() {
                payload
                    .write_u16::<LittleEndian>(segment)
                    .expect("Failed to add IPV6 segment from to the payload");
            }
        }
    }
    payload
        .write_u16::<LittleEndian>(add.port())
        .expect("Failed to add seriliazed address to the payload");
}