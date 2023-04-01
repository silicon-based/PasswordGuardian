use getrandom::getrandom;
pub fn generate_salt() -> [u8; 16] {
    let mut dest = [0u8; 16];
    getrandom(&mut dest).unwrap();
    dest
}
pub mod encryption {
    use aes_kw::KekAes256;
    use fernet::{DecryptionError, Fernet};

    /// The cipher that encrypts the passwords.
    pub struct Cipher {
        fernet: Fernet,
    }

    impl Cipher {
        /// Generate cipher by hashing password as KEK and unwrap WRAP
        /// `EKEY = AES-KW^-1(WRAP, Argon2(PASS, SALT))`
        pub fn from_unwrap(kek: [u8; 32], wrapped_key: [u8; 40]) -> Result<Self, aes_kw::Error> {
            let kek_cipher = KekAes256::from(kek);
            let mut decrypted_key = [0u8; 32];
            kek_cipher.unwrap(&wrapped_key, &mut decrypted_key)?;
            let fernet = Fernet::new(&base64_url::encode(&decrypted_key)).unwrap();

            Ok(Self { fernet })
        }

        pub fn encrypt(&self, data: &[u8]) -> String {
            self.fernet.encrypt(data)
        }

        pub fn decrypt(&self, ciphertext: &str) -> Result<Vec<u8>, DecryptionError> {
            match self.fernet.decrypt(ciphertext) {
                Ok(decrypted) => Ok(decrypted),
                Err(e) => Err(e),
            }
        }

        pub fn generate_key() -> String {
            Fernet::generate_key()
        }
    }
    #[cfg(test)]
    mod test {
        use super::Cipher;

        #[test]
        fn create() {
            let kek: [u8; 32] = base64_url::decode("QR66Cx_3lGU-R3TMWEivbx8I00qXgdHMdJxer92LSo8")
                .unwrap()
                .try_into()
                .unwrap();
            let wrap: [u8; 40] =
                base64_url::decode("3PV8v4uITiZ9scpB7usBBoFPClGoH5XnMQSeneM3_Z3FfbZ6PzE1ag")
                    .unwrap()
                    .try_into()
                    .unwrap();
            assert!(Cipher::from_unwrap(kek, wrap).is_ok());
        }

        #[test]
        fn decrypt() {
            let kek: [u8; 32] = base64_url::decode("QR66Cx_3lGU-R3TMWEivbx8I00qXgdHMdJxer92LSo8")
                .unwrap()
                .try_into()
                .unwrap();
            let wrap: [u8; 40] =
                base64_url::decode("3PV8v4uITiZ9scpB7usBBoFPClGoH5XnMQSeneM3_Z3FfbZ6PzE1ag")
                    .unwrap()
                    .try_into()
                    .unwrap();
            let cipher = Cipher::from_unwrap(kek, wrap).unwrap();
            let plaintext = "Secrets!";
            let ciphertext = cipher.encrypt(plaintext.as_bytes());
            let decrypted = cipher.decrypt(&ciphertext);
            assert!(decrypted.is_ok());
            assert_eq!(decrypted.unwrap(), plaintext.as_bytes());
        }
    }
}

pub mod kdf {
    use argon2::{self, Config, ThreadMode, Variant, Version};
    pub fn derive_kek(plaintext: &str, salt: &[u8]) -> [u8; 32] {
        const ARGON2_CONFIG: Config<'_> = Config {
            ad: &[],
            hash_length: 32,
            lanes: 4,
            mem_cost: 65536,
            secret: &[],
            thread_mode: ThreadMode::Sequential,
            time_cost: 8,
            variant: Variant::Argon2i,
            version: Version::Version13,
        };
        let derived_key = argon2::hash_raw(plaintext.as_bytes(), salt, &ARGON2_CONFIG).unwrap();
        assert_eq!(derived_key.len(), 32);
        derived_key.try_into().unwrap()
    }
}
