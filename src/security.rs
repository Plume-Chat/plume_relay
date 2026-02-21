use std::{str::FromStr, env};

use ed25519_dalek::{ed25519::signature, pkcs8::DecodePublicKey, Signature, VerifyingKey};

/// Verify the signature of a given packet.
/// Remember, a packet will always follow same structure : 
///
/// ```
/// <type_packet>--<author_ed25519>--[infos supplémentaires]--<signature_auteur>
/// ```
/// So this function verify if the last data of the packet (signature so) can verify the whole rest
/// of it and return a boolean corresponding to if it succeded or not
///
/// WARN: A possible upgrade of this function would be to return a Result<bool, Enum> with a
/// complete load of possible error cause so custom messages can be returned to senders
pub fn verify_packet_signature(packet: String) -> bool{
    let environment = env::var("ENV").unwrap_or_default();

    // disable verify_packet_signature in dev env or if SECURITY is disabled
    if environment == "DEV" {
        return true
    }


    let mut split_informations: Vec<&str> = packet.split("__").collect();

    if split_informations.len() < 3 {
        return false
    }

    if let Ok(key) = VerifyingKey::from_public_key_pem(&split_informations[1]) {
        // Now we can verify message by joining all remaining elements with -- and compare the
        // signature + key with it


        if let Ok(signature) = Signature::from_str(split_informations.pop().unwrap()) {
            let content = split_informations.join("__");
            println!("Veriying string : {}", content);

            match key.verify_strict(&content.as_bytes(), &signature) {
                Ok(_) => {
                    return true;
                },
                Err(_) => {
                    return false;
                }
            }
        }     

        println!("Invalid Signature format")

    } 

    println!("Invalid key : {}", &split_informations[1]);
    return false
}
