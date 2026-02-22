use ed25519_dalek::{ed25519::signature, pkcs8::spki};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::security::verify_packet_signature;

/// Differents types of packets, all new packets will be added here
pub enum Packet {
    Login(LoginData),
    Message(MessageData),
    FriendRequest(FriendRequestData),
    RetrievePublished(RetrievePublishedData),
}

/// All the reason why a packet extraction may fail. 
/// **Type** means that the packet is not recognised
/// **Data** means that the packet content isn't correctly split or is simply missing
/// **Signature** Means that the signature was incorrect
/// **Key** Means that the key was incorrect
pub enum PacketError {
    Type,
    Data,
    Signature,
    Key // invalid key given
}

impl From<serde_json::Error> for PacketError {
    fn from(_: serde_json::Error) -> Self {
        PacketError::Data
    }
}

impl From<spki::Error> for PacketError {
    fn from(_: spki::Error) -> Self {
        PacketError::Key
    }
}

impl From<signature::Error> for PacketError {
    fn from(_: signature::Error) -> Self {
        PacketError::Signature
    }
}

/// Data provided for the message packet
/// Date is in ISO 8601 format
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MessageData {
    pub author_key: String,
    pub recipent: String,
    pub sent_at: String, 
    pub content: String,
    pub signature: String
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct LoginData {
    pub author_key: String,
    pub signature: String
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FriendRequestData {
    pub author_key: String,
    pub recipent: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RetrievePublishedData {
}


/// Transform a json string into a packet with all the necessary data and verify it's signature
///
/// packet_data is a collections or all the data required for this packet in order and split by "__".  
/// **Example**:
/// ```rust
/// use plume::packet;
///
/// let login_packet = r#"
///     {
///         "type": "login",
///         "author_key": "<MyKey>"
///     }"#;
/// let received = String::from(login_packet);
/// let packet: Packet = extract_packet(received);
/// ```
///
pub fn extract_and_verify (data: &str) -> Result<Packet, PacketError> {
    let packet = extract(data)?;

    verify_packet_signature(&packet)?;

    Ok(packet)
}

pub fn extract(data: &str) -> Result<Packet, PacketError> {
    let packet: Value = serde_json::from_str(data)?;
    let packet_type = packet["action"].as_str().unwrap_or_default();
    println!("Packet Type is : {}", packet_type);

    match packet_type {
        "login" => {
            Ok(Packet::Login(serde_json::from_str(data)?))
        }
        "message" => {
            Ok(Packet::Message(serde_json::from_str(data)?))
        }
        "friend_request" => {
            todo!()
            // Ok(Packet::FriendRequest(serde_json::from_str(data)?))
        }
        _ => {
            Err(PacketError::Type)
        }
    }
}
