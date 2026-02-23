use std::{
    collections::HashMap, env, fs::{self, File}, io::{BufReader, Error as IoError}, net::SocketAddr, sync::{Arc, Mutex}
};

use futures_channel::mpsc::{unbounded, UnboundedSender};
use futures_util::{StreamExt, future, pin_mut, stream::TryStreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;

mod database;

use database::commande::Commandes;

use plume_core::{config::get_config, encryption::signature::sign_packet, packets::{AnnouncementData, ErrorData, Packet, PacketReadingError, RelayPacketGeneration, extract_and_verify}};

type Tx = UnboundedSender<Message>;
type PeerMap = Arc<Mutex<HashMap<SocketAddr, Tx>>>;
type KeysMap = Arc<Mutex<HashMap<String, Tx>>>;

async fn handle_connection(peer_map: PeerMap, raw_stream: TcpStream, addr: SocketAddr, keys_map: KeysMap) {
    println!("Incoming TCP connection from: {}", addr);
    let mut authenticated_key: Option<String> = None;

    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .expect("Error during the websocket handshake occurred");
    println!("WebSocket connection established: {}", addr);

    // Insert the write part of this peer to the peer map.
    let (tx, rx) = unbounded();
    peer_map.lock().unwrap().insert(addr, tx.clone());

    let (outgoing, incoming) = ws_stream.split();

    let handle_messages = incoming.try_for_each(|msg| {
        println!("Received a message from {}: {}", addr, msg.to_text().unwrap());
        let peers = peer_map.lock().unwrap();

        let msg_string = msg.to_text().expect("Unable to get string version of the packet");
        let packet = extract_and_verify(msg_string);

        match packet {
            Ok(Packet::FriendRequest(request_data)) => {
                let keys = keys_map.lock().expect("Keys map already locked by current thread");

                let content = serde_json::to_string(&request_data).unwrap_or_default();
                let msg = Message::text(&content);

                if let Some(recipient_conn) = keys.get(&request_data.recipient) {
                    recipient_conn.unbounded_send(msg).unwrap();
                } else {
                    // TODO: Wait for BDD to store pending message
                    todo!("Store the message waiting for the user to connect")
                }
            }
            Ok(Packet::RetrievePublished(_)) => {
                todo!("Retrieve the published key of the user in the database/home/fuyuki/Downloads/Plume-documentation.html")
            }
            Ok(Packet::Message(message_data)) => {
                let keys = keys_map.lock().unwrap();

                let content = serde_json::to_string(&message_data).unwrap_or_default();
                let msg = Message::text(&content);

                if let Some(recipient_conn) = keys.get(&message_data.recipient) {
                    recipient_conn.unbounded_send(msg).unwrap();
                } else {
                    // TODO: Wait for BDD to store pending message
                    todo!("Store the message waiting for the user to connect")
                }
            }
            Ok(Packet::Login(request_data)) => {
                let mut response = Packet::Announcement(AnnouncementData::new(&format!("Successfully logged in using the following key : {}", request_data.headers.author_key)));
                let mut keys = keys_map.lock().expect("Key maps is already locked in the same thread");
                authenticated_key = Some(request_data.headers.author_key.clone());
                keys.insert(request_data.headers.author_key, tx.clone());

                reply_user(addr, &peers, &mut response);
            }
            Ok(Packet::Register(_)) => {
                // TODO: Wait for database module to be fixed
                todo!("Handle storing the user in the user table of the relay");
            }
            Ok(Packet::Announcement(_)) => {
                let mut response = Packet::Error(ErrorData::new("Relay does not handle this kinds of packet"));
                reply_user(addr, &peers, &mut response);
            }
            Ok(Packet::Error(_)) => {
                let mut response = Packet::Error(ErrorData::new("Relay does not handle this kinds of packet"));
                reply_user(addr, &peers, &mut response);
            }
            Err(PacketReadingError::Signature) => {
                let mut response = Packet::Error(ErrorData::new("Invalid payload, signature did not match"));
                reply_user(addr, &peers, &mut response);
            }
            Err(PacketReadingError::Data) => {
                todo!()
            }
            Err(PacketReadingError::Type) => {
                let mut response = Packet::Error(ErrorData::new("Unknown packet type"));
                reply_user(addr, &peers, &mut response);
            }
            Err(PacketReadingError::Key) => {
                let mut response = Packet::Error(ErrorData::new("Invalid key given"));
                reply_user(addr, &peers, &mut response);
            }
        }

        // TODO: Log each packet

        future::ok(())
    });

    let receive_from_others = rx.map(Ok).forward(outgoing);

    pin_mut!(handle_messages, receive_from_others);
    future::select(handle_messages, receive_from_others).await;

    println!("{} disconnected", &addr);
    peer_map.lock().unwrap().remove(&addr);
    if let Some(key) = authenticated_key {
        keys_map.lock().unwrap().remove(&key); // also remove the key from connection list
    }
}


/// Send a message to a peer based on his address
/// This function is mainly destined to be used by error handling, since other cases will be
/// handled by key match for peer.
///
/// Example : 
/// ```rust
/// match packet {
///     _ => {
///         let message = serde_json::to_string(&RelayMessage::new("error", "Invalid key given")).unwrap_or_default();
///         reply_user(addr, &peers, &message);
///     }
/// }
/// ```
fn reply_user(user_addr: SocketAddr, peers_map: &HashMap<SocketAddr, Tx>, packet: &mut Packet) {
    // First sign the packet
    let relay_private_path = get_config().me.private_ed_path;
    let relay_private = fs::read_to_string(relay_private_path).expect("Couldn't read the private key from the server");
    sign_packet(packet, &relay_private).expect("Invalid relay signing key");

    match packet {
        Packet::Announcement(announcement) => {
            let message = Message::text(serde_json::to_string(announcement).unwrap_or_default());
            if let Some(peer) = peers_map.get(&user_addr) {
                peer.unbounded_send(message).unwrap();
            } else {
                println!("Unable to get the sender ({}) in the peers_map to send back error message", user_addr);
            }
        }
        Packet::Error(error) => {
            let message = Message::text(serde_json::to_string(error).unwrap_or_default());
            if let Some(peer) = peers_map.get(&user_addr) {
                peer.unbounded_send(message).unwrap();
            } else {
                println!("Unable to get the sender ({}) in the peers_map to send back error message", user_addr);
            }
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), IoError> {
    let mut db_client: database::Database = database::Database { plume: database::connection::connection_database().await.expect("Erreur lors de la connection") };
    db_client.show_user_tables().await;
    //Panic si la db n'est pas lancé

    init();

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

fn init() {
    plume_core::init();

    // Then Check for config, if user does not have key then propose to generate one or insert an existing one
    let config_path = env::var("PLUME_CONFIG").expect("Config env var not set");
    let config_file = File::open(format!("{}/configs.json", config_path)).expect("Eror opening config file");
    let reader = BufReader::new(config_file);

    let mut configs: plume_core::config::Config = serde_json::from_reader(reader).expect("Unable to convert this file to json");

    // if no ed then generate a new one
    if configs.me.public_ed_path.is_empty() {
        println!("Generating keys");
        let (private_ed, public_ed) = plume_core::encryption::keys::generate_ed_keys();
        // Then store them in a file
        
        fs::write(format!("{}/keys/private_ed.pem", config_path), &private_ed).expect("Unable to save private key file");
        fs::write(format!("{}/keys/public_ed.pem", config_path), &public_ed).expect("Unable to save public key file");

        configs.me.public_ed_path = format!("{}/keys/public_ed.pem", public_ed);
        configs.me.private_ed_path = format!("{}/keys/private_ed.pem", private_ed);
        plume_core::config::update_config(&configs);
    }

    match fs::read(&configs.me.public_ed_path) {
        Ok(_) => {
            String::from_utf8(fs::read(&configs.me.private_ed_path).expect("Invalid file storing signing key")).expect("Invalid key stored in file");
        },
        Err(err) => {
            println!("Key path : {}", configs.me.public_ed_path);
            println!("{}", err);
            println!("Unable to locate previously generated key, setting up a new one ... ");

            let (private_ed, public_ed) = plume_core::encryption::keys::generate_ed_keys();
            // write the keys to files
            fs::write(format!("{}/keys/private_ed.pem", config_path), &private_ed).expect("Unable to write key to file");
            fs::write(format!("{}/keys/public_ed.pem", config_path), &public_ed).expect("Unable to write key to file");


            println!("Wrote keys to files");

            configs.me.public_ed_path = format!("{}/keys/public_ed.pem", config_path);
            configs.me.private_ed_path = format!("{}/keys/private_ed.pem", config_path);

            println!("{:?}", configs);

            let json = serde_json::json!(configs);
            fs::write(format!("{}/configs.json", config_path),  serde_json::to_vec(&json).expect("Unable to transform string to json")).expect("Unable to write config file");

            println!("Config file updated");

            println!("\n\n Your public key is : \n{}", public_ed);
        }
    }
}
