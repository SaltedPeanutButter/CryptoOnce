use aes_gcm::{Aes256Gcm, Key};
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
use rand::seq::SliceRandom;
use once_cell::sync::Lazy;

static WORD_LIST: Lazy<Vec<String>> = Lazy::new(|| {
    let content = include_str!("../words.txt");
    let content = content
        .split('\n')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    content
});


/// Anything that implements this trait can be used as encryption key for [`CryptoOnce`](crate).
/// The only required method is [`CKey::to_key`].
pub trait CKey where Self: Clone {
    /// (Required) Self-consume to produce input material for KDF.
    fn consume(self) -> Vec<u8>;

    /// (Optional) Create a salt for PBKDF2. Strongly recommended to re-implement if
    /// user privacy is important.
    fn salt(&self) -> Vec<u8> {
        b"unsalted".to_vec()
    }

    /// Optional. Apply PBKDF2 to get the internal key.
    fn make_key(self) -> Key<Aes256Gcm> {
        // 256-bit key
        let mut key = [0u8; 32];
        let salt = self.salt();
        pbkdf2_hmac::<Sha256>(&self.consume(), &salt, 600000, &mut key);
        key.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WordKey(Vec<String>);

impl WordKey {
    /// Create a 4-word key. Use [`WordKey::from_size`] to specify a different length.
    pub fn new() -> WordKey {
        Self::from_size(4)
    }

    /// Create a key with variable number of words. Note that this function panics if `size > 7557`
    /// (the size of the word list).
    pub fn from_size(size: usize) -> WordKey {
        assert!(size < WORD_LIST.len(), "WordKey size is larger than the total number of words");
        let words = WORD_LIST
            .choose_multiple(&mut rand::thread_rng(), 4)
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        Self(words)
    }
}

impl Default for WordKey {
    fn default() -> Self {
        Self::new()
    }
}

impl CKey for WordKey {
    fn consume(mut self) -> Vec<u8> {
        // Extremely important. Allows un-ordering the word list.
        self.0.sort();
        self.0.consume()
    }
}

impl CKey for &str {
    fn consume(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl CKey for String {
    fn consume(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl<T> CKey for Vec<T> where T: CKey {
    fn consume(self) -> Vec<u8> {
        let mut result = Vec::new();
        for item in self {
            result.extend(item.consume())
        }
        result
    }
}

impl<T, const N: usize> CKey for [T; N] where T: CKey {
    fn consume(self) -> Vec<u8> {
        let mut result = Vec::new();
        for item in self {
            result.extend(item.consume())
        }
        result
    }
}

impl<T> CKey for &[T] where T: CKey {
    fn consume(self) -> Vec<u8> {
        let mut result = Vec::new();
        for item in self {
            result.extend(item.clone().consume())
        }
        result
    }
}