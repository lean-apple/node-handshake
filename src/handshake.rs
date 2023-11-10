use super::messages::{BitcoinMessage, Serializable};
use super::network::BitcoinNetwork;
use super::vv::{Command, VerackMessage, VersionMessage};
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};

/// Establish a TCP connection to a Bitcoin node for one of its network
/// Performs the handshake protocol by sending the intial version, then  waiting for the reply
/// the verack message and finally closes the connection
/// *Arguments
/// network - network type between Mainnet, Testnet3 and Regtest
/// sender - sending node's socket address
/// receiver - receiving node's socket address
/// user_agent - user agent's string - //TODO: removed it or test with other value
/// start_height - node's block height
pub fn perform_handshake(
    network: BitcoinNetwork,
    sender: SocketAddr,
    receiver: SocketAddr,
    user_agent: String,
    start_height: i32,
) -> Result<(), Error> {
    let mut stream = TcpStream::connect(sender)?;

    // Create Version Message
    let version_message = VersionMessage::new(receiver, sender, user_agent, start_height, false);

    // Prepare Bitcoin message payload ready to be sent
    let vrs_msg_payload = version_message.serialize()?;

    // Build the Bitcoin Message with Version Type to initialize handshake
    let bitcoin_message = BitcoinMessage::new(Command::Version, vrs_msg_payload, network);

    let serialized_btc_msg = bitcoin_message
        .serialize()
        .expect("Bitcoin Message could not be serialized");

    stream.write_all(&serialized_btc_msg).unwrap();
    stream.flush().unwrap();

    let mut res_version_msg = [0; 24];

    match stream.read_exact(&mut res_version_msg) {
        Ok(_) => {
            // Read Verack message response and
            // Verify some of its content regarding the version message
            VerackMessage::deserialize_and_verify(
                res_version_msg.into(),
                network,
                Command::Version,
            )
            .unwrap();
        }
        Err(e) => {
            // Handle different error types
            match e.kind() {
                ErrorKind::UnexpectedEof => {
                    // Not enough bytes were available to read
                    eprintln!("Unexpected end of file: {:?}", e);
                }
                ErrorKind::WouldBlock => {
                    // The operation would block but the socket is set to non-blocking mode
                    eprintln!("Operation would block: {:?}", e);
                }
                _ => {
                    // Unspecified error occurred
                    eprintln!("Failed to read the version message answer: {:?}", e);
                }
            }
        }
    }

    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
}
