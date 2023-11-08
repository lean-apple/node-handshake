use super::message::{BitcoinMessage, Serializable};
use super::network::{serialize_socket_add, BitcoinNetwork};
use super::utils::{calculate_timestamp, generate_nonce, write_varint};
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::Error;
use std::net::SocketAddr;

// Constants for the Bitcoin protocol
// First 4 bytes of the double hash
pub const CHECKSUM_SIZE: usize = 4;
// Last version released in Jan 2017
const PROTOCOL_VERSION: i32 = 70015;

#[derive(Debug, Clone, Copy)]
pub enum Command {
    Version,
    Verack,
}

impl Command {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Command::Version => b"version",
            Command::Verack => b"verack",
        }
    }
}

#[derive(Debug)]
pub struct VersionMessage {
    version: i32,
    services: u64,
    timestamp: i64,
    receiver: SocketAddr,
    sender: SocketAddr,
    nonce: u64,
    user_agent: String,
    start_height: i32,
    relay: bool,
}

impl VersionMessage {
    pub fn new(
        receiver: SocketAddr,
        sender: SocketAddr,
        user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            services: 1,
            timestamp: calculate_timestamp(),
            receiver,
            sender,
            nonce: generate_nonce(),
            user_agent,
            start_height,
            relay,
        }
    }
    /// Create Bitcoin version Message
    pub fn create(
        network: BitcoinNetwork,
        receiver: SocketAddr,
        sender: SocketAddr,
        user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Result<BitcoinMessage, Error> {
        // Start constructing the payload
        let mut payload = Vec::new();
        payload.write_i32::<LittleEndian>(PROTOCOL_VERSION).unwrap();
        payload.write_u64::<LittleEndian>(1).unwrap();

        payload
            .write_i64::<LittleEndian>(calculate_timestamp())
            .unwrap();

        let services = 1;

        // Serialize the receiver's node network address
        serialize_socket_add(&mut payload, services, &receiver);

        // Serialize this sender's node network address
        serialize_socket_add(&mut payload, services, &sender);

        // Generate nonce to be added to the payload
        let nonce = generate_nonce();
        payload.write_u64::<LittleEndian>(nonce).unwrap();

        let user_agent_bytes = user_agent.as_bytes();
        // Variable user agent length integer
        write_varint(&mut payload, user_agent_bytes.len() as u64);
        payload.extend_from_slice(user_agent_bytes);

        payload.write_i32::<LittleEndian>(start_height).unwrap();
        payload.write_u8(relay as u8).unwrap();

        Ok(BitcoinMessage {
            command: Command::Version.as_bytes().to_vec(),
            payload,
            network,
        })
    }
}

impl Serializable for VersionMessage {
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        // Start constructing the payload
        let mut message = Vec::new();

        message.write_i32::<LittleEndian>(self.version)?;
        message.write_u64::<LittleEndian>(self.services)?;
        message.write_i64::<LittleEndian>(self.timestamp)?;
        message.write_i32::<LittleEndian>(PROTOCOL_VERSION)?;
        message.write_u64::<LittleEndian>(1)?;

        let tmstp = calculate_timestamp();
        message.write_i64::<LittleEndian>(tmstp)?;

        let services = 1;

        // Serialize the receiver node's (remote peer's) network address
        serialize_socket_add(&mut message, services, &self.receiver);

        // Serialize this sender node's network address
        serialize_socket_add(&mut message, services, &self.sender);

        message.write_u64::<LittleEndian>(self.nonce)?;

        let user_agent_bytes = self.user_agent.as_bytes();
        // Variable user agent length integer
        write_varint(&mut message, user_agent_bytes.len() as u64);
        message.extend_from_slice(user_agent_bytes);

        message.write_i32::<LittleEndian>(self.start_height)?;
        message.write_u8(self.relay as u8)?;

        Ok(message)
    }
}
