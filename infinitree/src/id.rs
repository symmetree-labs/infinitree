use crate::crypto::{Digest, SecureRandom};
pub use hex::FromHexError;
use std::{convert::TryFrom, string::ToString};

/// Unique identifier for a persistence object.
#[derive(Default, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Id(Digest);

impl Id {
    #[inline(always)]
    pub fn new(random: &impl SecureRandom) -> Id {
        let mut id = Id::default();
        id.reset(random);
        id
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Id {
        let mut id = Id::default();
        id.0.copy_from_slice(bytes.as_ref());

        id
    }

    #[inline(always)]
    pub fn reset(&mut self, random: &impl SecureRandom) {
        random.fill(&mut self.0).unwrap();
    }
}

impl AsRef<[u8]> for Id {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&str> for Id {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex::decode(value).map(Self::from_bytes)
    }
}

impl ToString for Id {
    #[inline(always)]
    fn to_string(&self) -> String {
        hex::encode(self.0.as_ref())
    }
}

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
