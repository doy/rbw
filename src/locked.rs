use zeroize::Zeroize as _;

const LEN: usize = 4096;

static REGION_LOCK_WORKS: std::sync::OnceLock<bool> =
    std::sync::OnceLock::new();

pub struct Vec {
    // `_lock` MUST be declared before `data` so `munlock` runs while `data`'s
    // backing allocation is still mapped (musl's mallocng `munmap`s freed 4KiB
    // allocations immediately, causing `munlock` to fail with ENOMEM).
    _lock: Option<region::LockGuard>,
    data: Box<arrayvec::ArrayVec<u8, LEN>>,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(arrayvec::ArrayVec::<_, LEN>::new());
        let lock = match REGION_LOCK_WORKS.get() {
            Some(true) => {
                Some(region::lock(data.as_ptr(), data.capacity()).unwrap())
            }
            Some(false) => None,
            None => match region::lock(data.as_ptr(), data.capacity()) {
                Ok(lock) => {
                    let _ = REGION_LOCK_WORKS.set(true);
                    Some(lock)
                }
                Err(e) => {
                    if REGION_LOCK_WORKS.set(false).is_ok() {
                        eprintln!("failed to lock memory region: {e}");
                    }
                    None
                }
            },
        };
        Self { _lock: lock, data }
    }
}

impl Vec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.truncate(0);
        self.data.extend(std::iter::repeat_n(0, LEN));
    }

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.zero();
        self.data.as_mut().zeroize();
    }
}

impl Clone for Vec {
    fn clone(&self) -> Self {
        let mut new_vec = Self::new();
        new_vec.extend(self.data().iter().copied());
        new_vec
    }
}

#[derive(Clone)]
pub struct Password {
    password: Vec,
}

impl Password {
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

pub const KEYS_LEN: usize = 64;

#[derive(Clone)]
pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEYS_LEN {
            return None;
        }
        let mut keys = Vec::new();
        keys.extend(bytes.iter().copied());
        Some(Self::new(keys))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.keys.data()[0..KEYS_LEN]
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: Vec,
}

impl PrivateKey {
    pub fn new(private_key: Vec) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &[u8] {
        self.private_key.data()
    }
}

#[derive(Clone)]
pub struct ApiKey {
    client_id: Password,
    client_secret: Password,
}

impl ApiKey {
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}

#[test]
fn test_keys_roundtrip_bytes() {
    let mut raw = [0_u8; KEYS_LEN];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }
    let keys = Keys::from_bytes(&raw).unwrap();
    assert_eq!(keys.as_bytes(), &raw);
    assert_eq!(keys.enc_key(), &raw[0..32]);
    assert_eq!(keys.mac_key(), &raw[32..64]);

    assert!(Keys::from_bytes(&[]).is_none());
    assert!(Keys::from_bytes(&raw[0..32]).is_none());
    assert!(Keys::from_bytes(&raw[0..63]).is_none());
    assert!(Keys::from_bytes(&[0_u8; 65]).is_none());
}
