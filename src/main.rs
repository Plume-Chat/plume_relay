use std::{
    collections::HashMap,
    env,
    io::Error as IoError,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::{future, pin_mut, stream::TryStreamExt, StreamExt};

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::{frame::coding::Data, Message};

mod security;
mod database;
mod packet;

use database::commande::Commandes;

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

        let split_msg: Vec<&str> = msg.to_text().expect("Unable to get string version of the message").split("__").collect();

        // First we check the kind of message received
        match split_msg[0] {
            "login" => {
                if split_msg.len() < 3 {
                    let message = Message::text("Invalid login request format");
                    // get the correct peers to send the message

                    let recipent = peers.iter().find(|(peer_addr, _)| peer_addr == &&addr);

                    match recipent {
                        Some(recp) => {
                            let (_, ws_sink) = recp;
                            ws_sink.unbounded_send(message).unwrap()
                        },
                        _ => {
                            println!("Unable to get the sender in the peers_map to send back error message");
                        }
                    }

                    return future::ok(());
                }

                if !security::verify_packet_signature(msg.to_string()) {
                    let environment = env::var("ENV");

                    // TODO: Upgrade security here (temp ban / warn)
                    let message = Message::text("error__Invalid payload, signature did not match");
                    if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                        let (_, websocker_peer) = peer;
                        websocker_peer.unbounded_send(message).unwrap();
                    } else {
                        println!("Unable to get the sender in the peers_map to send back connection message");
                    }
                    return future::ok(());
                }
                
                // If we get the key then register it in the array
                keys_map.lock().unwrap().insert(addr, split_msg[1].to_string());

                let message = Message::text(format!("announcement__Successfully logged in using the following key :\n{}", split_msg[1]));

                if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                    let (_, websocker_peer) = peer;
                    websocker_peer.unbounded_send(message).unwrap();
                } else {
                    println!("Unable to get the sender in the peers_map to send back connection message");
                }
            },
            "message" => {
                if !security::verify_packet_signature(msg.to_string()) {
                    let message = Message::text("error__Invalid payload, signature did not match");
                    if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                        let (_, websocker_peer) = peer;
                        websocker_peer.unbounded_send(message).unwrap();
                    } else {
                        println!("Unable to get the sender in the peers_map to send back connection message");
                    }
                    return future::ok(());
                }

                // We want to broadcast the message to everyone except ourselves.
                let broadcast_recipients =
                    peers.iter().filter(|(peer_addr, _)| peer_addr != &&addr).map(|(_, ws_sink)| ws_sink);

                for recp in broadcast_recipients {
                    let message = Message::text(format!("message__[{}] - {}",addr, msg.to_string().split("__").collect::<Vec<&str>>()[3])); // Sending the message to everyone
                    recp.unbounded_send(message).unwrap();
                }
            },
            "retrieve_published" => {
                if !security::verify_packet_signature(msg.to_string()) {
                    let message = Message::text("error__Invalid payload, signature did not match");
                    if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                        let (_, websocker_peer) = peer;
                        websocker_peer.unbounded_send(message).unwrap();
                    } else {
                        println!("Unable to get the sender in the peers_map to send back connection message");
                    }
                    return future::ok(());
                }
                
                // Check in the database if the given public key exist
                // True => return the published key
                // False => return an error telling user is not registered


                // for testing purpose we will return sample data
                let message = Message::text("published_x__{test published x}");

                // Return the message to the sender
                if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                    let (_, websocket_peer) = peer;
                    websocket_peer.unbounded_send(message).unwrap();
                }
            }
            "friend_request" => {
                let message = Message::text("Request friend received");
                if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                    let (_, websocker_peer) = peer;
                    websocker_peer.unbounded_send(message).unwrap();
                } else {
                    println!("Unable to get the sender in the peers_map to send back connection message");
                }
            },
            _ => {
                let message = Message::text("Packet pattern not recognized");
                if let Some(peer) = peers.iter().find(|(ip_addr, _)| ip_addr == &&addr) {
                    let (_, websocker_peer) = peer;
                    websocker_peer.unbounded_send(message).unwrap();
                } else {
                    println!("Unable to get the sender in the peers_map to send back error message");
                }
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


#[tokio::main]
async fn main() -> Result<(), IoError> {
    let mut db_client: database::Database = database::Database { plume: database::connection::connection_database().await.expect("Erreur lors de la connection") };
    db_client.show_user_tables().await;
    //Panic si la db n'est pas lancé

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
