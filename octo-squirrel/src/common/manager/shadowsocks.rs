use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Formatter;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;

use base64ct::Base64;
use base64ct::Encoding;
use byte_string::ByteStr;

use crate::config::User;

#[derive(Clone, Debug)]
pub struct ServerUserManager<const N: usize> {
    users: HashMap<[u8; 16], Arc<ServerUser<N>>>,
}

impl<const N: usize> ServerUserManager<N> {
    /// Create a new manager
    pub fn new() -> ServerUserManager<N> {
        ServerUserManager { users: HashMap::new() }
    }

    /// Add a new user
    pub fn add_user(&mut self, user: ServerUser<N>) {
        self.users.insert(user.identity_hash(), Arc::new(user));
    }

    /// Get user by hash key
    pub fn get_user_by_hash(&self, user_hash: &[u8]) -> Option<&ServerUser<N>> {
        self.users.get(user_hash).map(AsRef::as_ref)
    }

    /// Get user by hash key cloned
    pub fn clone_user_by_hash(&self, user_hash: &[u8]) -> Option<Arc<ServerUser<N>>> {
        self.users.get(user_hash).cloned()
    }

    /// Number of users
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Iterate users
    pub fn users_iter(&self) -> impl Iterator<Item = &ServerUser<N>> {
        self.users.values().map(|v| v.as_ref())
    }
}

impl Default for ServerUserManager<32> {
    fn default() -> ServerUserManager<32> {
        ServerUserManager::new()
    }
}

#[derive(Eq, Debug, Clone)]
pub struct ServerUser<const N: usize> {
    pub name: String,
    pub key: [u8; N],
    pub identity_hash: [u8; 16],
}

impl<const N: usize> ServerUser<N> {
    pub fn identity_hash(&self) -> [u8; 16] {
        self.identity_hash
    }

    pub fn from_user(value: &User) -> Result<Self, base64ct::Error> {
        let mut key = [0; N];
        let mut identity_hash = [0; 16];
        Base64::decode(&value.password, &mut key)?;
        let hash = blake3::hash(&key);
        identity_hash.copy_from_slice(&hash.as_bytes()[..16]);
        Ok(Self { name: value.name.clone(), key, identity_hash })
    }
}

impl<const N: usize> PartialEq for ServerUser<N> {
    fn eq(&self, other: &Self) -> bool {
        self.identity_hash == other.identity_hash
    }
}

impl<const N: usize> Hash for ServerUser<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity_hash.hash(state);
    }
}

impl<const N: usize> Display for ServerUser<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "N:{}, K:{:?}, IH:{:?}", self.name, ByteStr::new(&self.key), ByteStr::new(&self.identity_hash))
    }
}
