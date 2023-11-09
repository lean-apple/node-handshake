use super::messages::{BitcoinMessage, Serializable};
use super::network::BitcoinNetwork;
use super::vv::{Command, VersionMessage};
use std::io::{Error, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};

/// Establish a TCP connection to a Bitcoin node for one of its network
/// Performs the initial handshake protocol by exchanging version and verack messages
/// Parameters
/// network - network type between Mainnet, Testnet3 and Regtest
/// sender - sending node's socket address
/// receiver - receiving node's socket address
/// user_agent - user agent's string - not very useful now
/// start_height - node's block height
pub fn perform_handshake(
    network: BitcoinNetwork,
    sender: SocketAddr,
    receiver: SocketAddr,
    user_agent: String,
    start_height: i32,
) -> Result<(), Error> {
    let mut stream = TcpStream::connect(sender)?;

    let version_message = VersionMessage::new(receiver, sender, user_agent, start_height, false);

    let vers_payload = version_message.serialize()?;

    let bitcoin_message = BitcoinMessage::new(Command::Version, vers_payload, network);

    let serialized_btc_msg = bitcoin_message
        .serialize()
        .expect("Bitcoin Message could not be serialized");

    stream.write_all(&serialized_btc_msg).unwrap();
    stream.flush().unwrap();

    let mut res_version_msg = [0; 24];

    let _ = stream.read_exact(&mut res_version_msg);

    //println!("res_vers_msg : {:?}", res_version_msg);

    // let des = BitcoinMessage::deserialize(res_version_msg.into()).unwrap();

    // println!("des version message {:?}", des);
    let _ = stream.shutdown(Shutdown::Both);

    Ok(())
}
