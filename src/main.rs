use std::{
    collections::HashMap, env, io::Error as IoError, net::SocketAddr, sync::{Arc, Mutex}
};

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::{StreamExt, future, pin_mut, stream::TryStreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;

mod security;
mod database;
mod packet;

use database::commande::Commandes;

use crate::packet::{Packet, PacketError, PacketGeneration, RelayMessage, extract_and_verify};

type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<SocketAddr, Tx>>>;
type KeysMap = Arc<Mutex<HashMap<SocketAddr, String>>>;

async fn handle_connection(peer_map: PeerMap, raw_stream: TcpStream, addr: SocketAddr, keys_map: KeysMap) {
    println!("Incoming TCP connection from: {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake occurred");
    println!("WebSocket connection established: {}", addr);

    // Insert the write part of this peer to the peer map.
    let (tx, rx) = unbounded();
    peer_map.lock().unwrap().insert(addr, tx);

    let (outgoing, incoming) = ws_stream.split();

    let handle_messages = incoming.try_for_each(|msg| {
        println!("Received a message from {}: {}", addr, msg.to_text().unwrap());
        let peers = peer_map.lock().unwrap();

        let msg_string = msg.to_text().expect("Unable to get string version of the packet");
        let packet = extract_and_verify(&msg_string);

        match packet {
            Ok(Packet::FriendRequest(_)) => {
                let message = Message::text("Request friend received");
                if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                    let (_, websocker_peer) = peer;
                    websocker_peer.unbounded_send(message).unwrap();
                } else {
                    println!("Unable to get the sender in the peers_map to send back connection message");
                }
            }
            Ok(Packet::RetrievePublished(_)) => {
                let message = Message::text("published_x__{test published x}");

                // Return the message to the sender
                if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                    let (_, websocket_peer) = peer;
                    websocket_peer.unbounded_send(message).unwrap();
                }
            }
            Ok(Packet::Message(message_data)) => {
                let keys = keys_map.lock().unwrap();
                let recipent_address = keys.iter().filter(|(_, key)| key == &&message_data.recipient).map(|(addr, _)| addr).collect::<Vec<&SocketAddr>>();

                let content = serde_json::to_string(&message_data).unwrap_or_default();

                for recp_addr in recipent_address {
                    if let Some(recipent_conn) = peers.get(&addr) {
                        let msg = Message::text(&content);
                        recipent_conn.unbounded_send(msg).unwrap();
                    }
                }
            }
            Ok(Packet::Login(request_data)) => {
                let message = serde_json::to_string(&RelayMessage::new("announcement", &format!("Successfully logged in using the following key : {}", request_data.author_key))).unwrap();
                reply_user(addr, &peers, &message);
            }
            Err(PacketError::Signature) => {
                let message = serde_json::to_string(&RelayMessage::new("error", "Invalid payload, signature did not match")).unwrap();
                reply_user(addr, &peers, &message);
            }
            Err(PacketError::Data) => {
                todo!()
            }
            Err(PacketError::Type) => {
                let message = serde_json::to_string(&RelayMessage::new("error", "Unknown packet type")).unwrap();
                reply_user(addr, &peers, &message);
            }
            Err(PacketError::Key) => {
                let message = serde_json::to_string(&RelayMessage::new("error", "Invalid key given")).unwrap();
                reply_user(addr, &peers, &message);
            }
        }

        future::ok(())
    });

    let receive_from_others = rx.map(Ok).forward(outgoing);

    pin_mut!(handle_messages, receive_from_others);
    future::select(handle_messages, receive_from_others).await;

    println!("{} disconnected", &addr);
    peer_map.lock().unwrap().remove(&addr);
    keys_map.lock().unwrap().remove(&addr); // also remove the key from connection list
}


fn reply_user(user_addr: SocketAddr, peers_map: &HashMap<SocketAddr, Tx>, message: &str) {
    let message = Message::text(message);
    if let Some(peer) = peers_map.get(&user_addr) {
        peer.unbounded_send(message).unwrap();
    } else {
        println!("Unable to get the sender in the peers_map to send back error message");
    }
}

#[tokio::main]
async fn main() -> Result<(), IoError> {
    let mut db_client: database::Database = database::Database { plume: database::connection::connection_database().await.expect("Erreur lors de la connection") };
    db_client.show_user_tables().await;
    //Panic si la db n'est pas lancé

    plume_core::init();

    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:8081".to_string());

    let state = PeerMap::new(Mutex::new(HashMap::new()));
    let users_keys = KeysMap::new(Mutex::new(HashMap::new()));

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    println!("Listening on: {}", addr);

    // Let's spawn the handling of each connection in a separate task.
    while let Ok((stream, addr)) = listener.accept().await {
        tokio::spawn(handle_connection(state.clone(), stream, addr, users_keys.clone()));
    }

    Ok(())
}
