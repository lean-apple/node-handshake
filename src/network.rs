use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Error, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Different Bitcoin networks
#[derive(Debug, Clone, Copy)]
pub enum BitcoinNetwork {
    // Main Network
    Mainnet,
    // Regression Test network, easiest for development
    Regtest,
    // Test Network
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
    pub fn as_u32(&self) -> u32 {
        u32::from_le_bytes(self.magic())
    }
}

/// Helper to serialize IP address either V4 or V6
/// For the Bitcoin protocol, when serializing data structures such as network addresses
/// Each address is prefixed with the services field
/// Once the address is serialized, it is added to the payload
pub fn add_serialize_addr(
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
            payload.extend(&add_v4.ip().octets());
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

/// Helper to deserialize a SocketAddr from a slice of bytes
pub fn read_deserialized_add(cursor: &mut std::io::Cursor<Vec<u8>>) -> Result<SocketAddr, Error> {
    let _services = cursor.read_u64::<LittleEndian>()?;

    // Check if we have an IPv4-mapped IPv6 address or a regular IPv6 address
    let mut addr_buf = [0u8; 16];
    cursor.read_exact(&mut addr_buf)?;

    let addr = if addr_buf[..10] == [0u8; 10] && addr_buf[10..12] == [0xff, 0xff] {
        // If it is IPv4-mapped IPv6 address
        let ipv4_bytes = &addr_buf[12..16];
        let ipv4_addr = Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);
        SocketAddr::V4(SocketAddrV4::new(
            ipv4_addr,
            cursor.read_u16::<LittleEndian>()?,
        ))
    } else {
        // If it is a regular IPv6 address
        let ipv6_addr = Ipv6Addr::from(addr_buf);
        SocketAddr::V6(SocketAddrV6::new(
            ipv6_addr,
            cursor.read_u16::<LittleEndian>()?,
            0,
            0,
        ))
    };
    Ok(addr)
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

        assert!(add_serialize_addr(&mut payload, services, &add).is_ok());
        assert_eq!(payload.len(), 26);
    }

    #[test]
    fn test_add_ipv6_to_payload_ok() {
        let mut payload = Vec::new();
        let services = 1u64;
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let port = 8080;

        let add = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));

        assert!(add_serialize_addr(&mut payload, services, &add).is_ok());
        assert_eq!(payload.len(), 26);
    }
}
