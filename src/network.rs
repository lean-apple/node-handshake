use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Error;
use std::net::SocketAddr;

/// Different Bitcoin networks
#[derive(Debug, Clone, Copy)]
pub enum BitcoinNetwork {
    // Main Network
    Mainnet,
    // Regression testnet network, easiest for development
    Regtest,
    // Testnet network
    Testnet3,
}

impl BitcoinNetwork {
    // Returns the magic value for every network
    pub fn magic(&self) -> [u8; 4] {
        match *self {
            BitcoinNetwork::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9], // 0xD9B4BEF9
            BitcoinNetwork::Regtest => [0xfa, 0xbf, 0xb5, 0xda], // 0xDAB5BFFA
            BitcoinNetwork::Testnet3 => [0x0b, 0x11, 0x09, 0x07], // 0x0709110B
        }
    }
}

/// Helper to serialize IP address either V4 or V6 address
/// In Bitcoin protocol, when serializing data structures such as network addresses
/// Each address is often prefixed with the services field
/// Once the address is serialized, it is added to the payload
pub fn serialize_socket_add(
    payload: &mut Vec<u8>,
    services: u64,
    add: &SocketAddr,
) -> Result<(), Error> {
    payload.write_u64::<LittleEndian>(services)?;
    match add {
        SocketAddr::V4(add_v4) => {
            // Serialize the IPv4 address in IPv6-mapped format ::ffff:0:0/96 prefix
            // First 10 bytes are zeros
            payload.extend(&[0; 10]);
            // Next 2 bytes are 0xff representing IPv4-mapping
            payload.extend(&[0xff, 0xff]);
            // IPv4 address
            payload.extend_from_slice(&add_v4.ip().octets());
        }
        SocketAddr::V6(add_v6) => {
            // Serialize the IPv6 address directly
            for &segment in &add_v6.ip().segments() {
                payload.write_u16::<LittleEndian>(segment)?
            }
        }
    }
    payload.write_u16::<LittleEndian>(add.port())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_add_ipv4_to_payload_ok() {
        let mut payload = Vec::new();
        let services = 1u64;
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 8080;
        let add = SocketAddr::V4(SocketAddrV4::new(ip, port));

        assert!(serialize_socket_add(&mut payload, services, &add).is_ok());
        assert_eq!(payload.len(), 26);
    }

    #[test]
    fn test_add_ipv6_to_payload_ok() {
        let mut payload = Vec::new();
        let services = 1u64;
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let port = 8080;

        let add = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));

        assert!(serialize_socket_add(&mut payload, services, &add).is_ok());
        assert_eq!(payload.len(), 26);
    }
}
