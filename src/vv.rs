use super::messages::Serializable;
use super::network::{deserialize_socket_add, serialize_socket_add};
use super::utils::{calculate_timestamp, generate_nonce};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Error, ErrorKind};
use std::net::SocketAddr;

// Constants for the Bitcoin protocol
// Last version released in Jan 2017
const PROTOCOL_VERSION: i32 = 70001i32;

#[derive(Debug, Clone, Copy)]
pub enum Command {
    Version,
    Verack,
}

impl Command {
    pub fn as_str(&self) -> &str {
        match self {
            Command::Version => "version",
            Command::Verack => "verack",
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        self.as_str().as_bytes().to_vec()
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
    _user_agent: String,
    start_height: i32,
    relay: bool,
}

impl VersionMessage {
    pub fn new(
        receiver: SocketAddr,
        sender: SocketAddr,
        _user_agent: String,
        start_height: i32,
        relay: bool,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            services: 0x1,
            timestamp: calculate_timestamp(),
            receiver,
            sender,
            nonce: generate_nonce(),
            _user_agent,
            start_height,
            relay,
        }
    }
}

impl Serializable for VersionMessage {
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut message = Vec::new();

        // Constructing the payload adding all version message elements
        message.extend(&self.version.to_le_bytes());
        message.extend(&self.services.to_le_bytes());
        message.extend(&self.timestamp.to_le_bytes());

        // Serialize the receiver node's (remote peer's) network address
        serialize_socket_add(&mut message, self.services, &self.receiver)?;

        // Serialize this sender node's network address
        serialize_socket_add(&mut message, self.services, &self.sender)?;

        // Add nonce to the payload
        message.write_u64::<LittleEndian>(self.nonce)?;
        // Allocation for the user agent
        message.extend(&[0]);
        message.write_i32::<LittleEndian>(self.start_height)?;
        message.write_u8(self.relay as u8)?;
        // Allocation for the relay
        message.extend(&[0]);
        Ok(message)
    }

    fn deserialize(msg: Vec<u8>) -> Result<Box<Self>, Error> {
        let mut cursor = Cursor::new(msg);

        let version = cursor.read_i32::<LittleEndian>()?;
        if version < PROTOCOL_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Unsupported protocol version",
            ));
        }

        let services = cursor.read_u64::<LittleEndian>()?;
        let timestamp = cursor.read_i64::<LittleEndian>()?;

        let receiver = deserialize_socket_add(&mut cursor)?;
        let sender = deserialize_socket_add(&mut cursor)?;

        let user_agent_byte = cursor.read_u8()?;

        let nonce = cursor.read_u64::<LittleEndian>()?;
        let start_height = cursor.read_i32::<LittleEndian>()?;
        let relay = cursor.read_u8()? > 0;

        Ok(Box::new(VersionMessage {
            version,
            services,
            timestamp,
            receiver,
            sender,
            nonce,
            _user_agent: user_agent_byte.to_string(),
            start_height,
            relay,
        }))
    }
}
