use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;

pub struct AttestedSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    pubkey_quote: Option<String>,
    container_signatures: Vec<String>,
}

impl AttestedSigner {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
            pubkey_quote: None,
            container_signatures: Vec::new(),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn set_pubkey_quote(&mut self, quote: String) {
        self.pubkey_quote = Some(quote);
    }

    pub fn get_pubkey_quote(&self) -> Option<&str> {
        self.pubkey_quote.as_deref()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn sign_container_hashes(&mut self, hashes: &[[u8; 48]]) -> anyhow::Result<()> {
        self.container_signatures.clear();

        for hash in hashes {
            let signature = self.sign(hash);
            let sig_hex = hex::encode(signature.to_bytes());
            self.container_signatures.push(sig_hex);
        }

        Ok(())
    }

    pub fn get_container_signatures(&self) -> &[String] {
        &self.container_signatures
    }

    pub fn get_signing_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}
