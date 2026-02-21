use crate::security::verify_packet_signature;

/// Differents types of packets, all new packets will be added here
pub enum Packet<'a> {
    Login(LoginData),
    Message(MessageData<'a>),
    FriendRequest(FriendRequestData),
    RetrievePublished(RetrievePublishedData),
}

/// All the reason why a packet extraction may fail. 
/// InvalidPacket means that the packet is not recognised
/// InvalidData means that the packet content isn't correctly split or is simply missing
pub enum PacketError {
    PacketFormat,
    Data,
    Signature
}

/// Data provided for the message packet
pub struct MessageData<'a> {
    author_key: String,
    message: &'a str,
    recipent: &'a str,
    signature: String
}

pub struct LoginData {
    pub author_key: String,
    pub signature: String
}

pub struct FriendRequestData {

}

pub struct RetrievePublishedData {

}



/// Transform a string into a packet with all the necessary data and verify it's signature
/// Packet format is the following : 
/// ```text
/// <packet_type>__<author_ed_key>__[packet_data]__<signature>
/// ```
///
/// packet_data is a collections or all the data required for this packet in order and split by "__".  
/// **Example**:
/// ```rust
/// use plume::packet;
/// let received = String::from("login__myKey__signature");
/// let packet: Packet = extract_packet(received);
/// ```
///
pub fn extract_and_verify<'a> (data: &'a str) -> Result<Packet<'a>, PacketError> {
    let packet = extract(data)?;

    if !verify_packet_signature(data.to_string()) {
        return Err(PacketError::Signature);
    }

    Ok(packet)
}

pub fn extract<'a> (data: &'a str) -> Result<Packet<'a>, PacketError> {
    let packet_split: Vec<&str> = data.split("__").collect();

    if packet_split.is_empty() {
        return Err(PacketError::PacketFormat);
    }

    match *packet_split.first().expect("Unable to retrieve packet type") {
        "login" => {
            if packet_split.len() < 3 {
                return Err(PacketError::Data);
            }

            Ok(Packet::Login(LoginData { 
                author_key: packet_split[1].to_string(), 
                signature: packet_split[2].to_string() 
            }))
        }
        "message" => {
            if packet_split.len() < 5 {
                return Err(PacketError::Data);
            }

            Ok(Packet::Message(MessageData { 
                author_key: packet_split[1].to_string(), 
                message: packet_split[2],
                recipent: packet_split[3], 
                signature: packet_split[4].to_string()
            }))
        }
        "friend_request" => {
            todo!()
        }
        _ => {
            Err(PacketError::PacketFormat)
        }
    }
}
