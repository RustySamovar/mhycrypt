use std::path::Path;
use std::io::Read;
use std::fs;
use std::collections::HashMap;

use rand_mt::Mt64;

use openssl::pkey::{Private};
use openssl::rsa::{Rsa};
use serde::{Deserializer, Deserialize};
use serde::de::Error;

// Keys stuff
#[derive(Deserialize,Debug)]
pub struct RsaKeyInfo {
    pub key_id: u8,
    #[serde(deserialize_with = "deserialize_priv_key")]
    pub encrypt_key: Rsa<Private>,
    #[serde(deserialize_with = "deserialize_priv_key")]
    pub signing_key: Rsa<Private>,
}

fn deserialize_priv_key<'de, D>(deserializer: D) -> Result<Rsa<Private>, D::Error>
    where
        D: Deserializer<'de>,
{
    let private_key_pem: String = Deserialize::deserialize(deserializer)?;

    Rsa::private_key_from_pem(private_key_pem.as_bytes()).map_err(D::Error::custom)
}

pub struct Ec2bKeyPair {
    pub ec2b: Vec<u8>,
    pub xorpad: Vec<u8>,
}

pub fn mhy_xor(data: &mut [u8], key: &[u8])
{
    for (i, e) in data.iter_mut().enumerate() {
        *e ^= key[i % key.len()];
    }
}

pub fn mhy_generate_key(key: &mut [u8], seed: u64, legacy: bool)
{
    assert!(key.len() % 8 == 0);

    let mut mt = Mt64::new(seed);

    if !legacy {
        let seed = mt.next_u64();
        mt.reseed(seed);
        mt.next_u64();
    }

    // u64.to_be_bytes() or u64.to_le_bytes() ?
    for i in 0..key.len()/8 {
        let bytes = mt.next_u64().to_be_bytes();

        for (j, e) in bytes.iter().enumerate() {
            key[i*8 + j] = *e;
        }
    }
}

pub fn load_ec2b_keys(name: &str, key_directory: &str) -> Ec2bKeyPair {
    // Key
    let filename = format!("./{}/{}.key", key_directory, name);
    let mut f = fs::File::open(&filename).expect(&format!("File '{}' not found", filename));
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut key = vec![0; metadata.len() as usize];
    f.read(&mut key).expect("buffer overflow");
    // Ec2b
    let filename = format!("./{}/{}.ec2b", key_directory, name);
    let mut f = fs::File::open(&filename).expect(&format!("File '{}' not found", filename));
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut ec2b = vec![0; metadata.len() as usize];
    f.read(&mut ec2b).expect("buffer overflow");

    Ec2bKeyPair {
        ec2b: ec2b,
        xorpad: key,
    }
}

pub fn load_rsa_keys(name: &str, key_directory: &str) -> HashMap<u8, RsaKeyInfo> {
    // Key depo
    let path = format!("./{}/{}.json", key_directory, name);
    let json_file_path = Path::new(&path);
    let json_file_str = fs::read_to_string(json_file_path).unwrap_or_else(|_| panic!("File {} not found", path));
    let data: Vec<RsaKeyInfo> = serde_json::from_str(&json_file_str).expect(&format!("Error while reading json {}", name));

    data.into_iter().map(|ki| (ki.key_id, ki)).collect()
}