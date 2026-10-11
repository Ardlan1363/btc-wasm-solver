use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Solver {
    target: [u8; 20],
    current: [u8; 32],
}

#[wasm_bindgen]
impl Solver {
    #[wasm_bindgen(constructor)]
    pub fn new(target_hex: &str) -> Result<Solver, JsValue> {
        let mut target = [0u8; 20];
        hex::decode_to_slice(target_hex, &mut target)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Solver {
            target,
            current: [0u8; 32],
        })
    }

    pub fn set_start(&mut self, start_hex: &str) -> Result<(), JsValue> {
        let start = hex::decode(start_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if start.len() != 32 {
            return Err(JsValue::from_str("start must be 32 bytes"));
        }
        self.current.copy_from_slice(&start);
        Ok(())
    }

    pub fn get_current(&self) -> String {
        hex::encode(&self.current)
    }

    pub fn search(&mut self, count: u32) -> String {
        for _ in 0..count {
            let sk = match SecretKey::from_slice(&self.current) {
                Ok(s) => s,
                Err(_) => {
                    self.increment();
                    continue;
                }
            };
            let pk = sk.public_key();
            let pk_bytes = pk.to_encoded_point(true);
            let sha = Sha256::digest(pk_bytes.as_bytes());
            let ripe = Ripemd160::digest(&sha);

            if ripe[..] == self.target[..] {
                return hex::encode(&self.current);
            }

            self.increment();
        }
        String::new()
    }

    #[inline(always)]
    fn increment(&mut self) {
        for i in (0..32).rev() {
            if self.current[i] == 0xFF {
                self.current[i] = 0;
            } else {
                self.current[i] += 1;
                break;
            }
        }
    }
}

#[wasm_bindgen]
pub fn check_key(priv_hex: &str, target_hex: &str) -> bool {
    let priv_bytes = match hex::decode(priv_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let target = match hex::decode(target_hex) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if target.len() != 20 || priv_bytes.len() != 32 {
        return false;
    }
    let sk = match SecretKey::from_slice(&priv_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_bytes = pk.to_encoded_point(true);
    let sha = Sha256::digest(pk_bytes.as_bytes());
    let ripe = Ripemd160::digest(&sha);
    ripe[..] == target[..]
}

#[wasm_bindgen]
pub fn priv_to_hash160(priv_hex: &str) -> String {
    let priv_bytes = match hex::decode(priv_hex) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let sk = match SecretKey::from_slice(&priv_bytes) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let pk = sk.public_key();
    let pk_bytes = pk.to_encoded_point(true);
    let sha = Sha256::digest(pk_bytes.as_bytes());
    let ripe = Ripemd160::digest(&sha);
    hex::encode(ripe)
}
