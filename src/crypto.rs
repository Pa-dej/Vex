use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key_der: Vec<u8>,
}

impl RsaKeyPair {
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 1024).context("generate rsa keypair")?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_der = public_key
            .to_public_key_der()
            .context("encode rsa public key to DER")?
            .as_ref()
            .to_vec();
        Ok(Self {
            private_key,
            public_key_der,
        })
    }

    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.private_key
            .decrypt(Pkcs1v15Encrypt, ciphertext)
            .context("rsa decrypt failed")
    }
}
