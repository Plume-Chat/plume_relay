pub struct MessageData {
    author_key: String,
    message: String,
    recipent: String,
    signature: String
}

pub enum Packet {
    Login(String),
    Message(MessageData)
}

pub fn extract_packet(data: String) {
}
