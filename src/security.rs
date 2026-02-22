use std::{str::FromStr, env};

use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, VerifyingKey};

use crate::packet::{Packet, PacketError};

/// Verify the signature of a given packet.
/// Packet are sent in json format, each packet will have it's own way to make the signature
/// payload
///
/// # Formats
/// ## Login
/// Signed payload is simply composed of the author key
/// ## Messages
/// Signed payload is author_key + recipent_key + content + sent_at
/// ## Friend Request
/// ## Retrieve Published
pub fn verify_packet_signature(packet: &Packet) -> Result<(), PacketError> {
    let environment = env::var("ENV").unwrap_or_default();

    // disable verify_packet_signature in dev env
    if environment == "DEV" {
        return Ok(())
    }


    match packet {
        Packet::Login(packet_data) => {
            let key = VerifyingKey::from_public_key_pem(&packet_data.author_key)?;
            let signature = Signature::from_str(&packet_data.signature)?;
            key.verify_strict(&packet_data.author_key.as_bytes(), &signature)?;
            
            return Ok(());
        }
        Packet::Message(packet_data) => {
            let payload = format!("{}{}{}{}", packet_data.author_key, packet_data.recipient,  packet_data.content, packet_data.sent_at);
            let key = VerifyingKey::from_public_key_pem(&packet_data.author_key)?;
            let signature = Signature::from_str(&packet_data.signature)?;
            key.verify_strict(payload.as_bytes(), &signature)?;

            Ok(())
        }
        Packet::FriendRequest(_) => {
            todo!()
        }
        Packet::RetrievePublished(_) => {
            todo!()
        }
    }
}
