use zeroize::Zeroize;

const LEN: usize = 4096;

pub struct Vec {
    data: Box<arrayvec::ArrayVec<u8, LEN>>,
    _lock: region::LockGuard,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(arrayvec::ArrayVec::<_, LEN>::new());
        // XXX it'd be nice to handle this better than .unwrap(), but it'd be
        // a lot of effort
        let lock = region::lock(data.as_ptr(), data.capacity()).unwrap();
        Self { data, _lock: lock }
    }
}

impl Vec {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    pub fn zero(&mut self) {
        self.truncate(0);
        self.data.extend(std::iter::repeat(0).take(LEN));
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
    #[must_use]
    pub fn new(password: Vec) -> Self {
        Self { password }
    }

    #[must_use]
    pub fn password(&self) -> &[u8] {
        self.password.data()
    }
}

#[derive(Clone)]
pub struct Keys {
    keys: Vec,
}

impl Keys {
    #[must_use]
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    #[must_use]
    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    #[must_use]
    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

#[derive(Clone)]
pub struct PasswordHash {
    hash: Vec,
}

impl PasswordHash {
    #[must_use]
    pub fn new(hash: Vec) -> Self {
        Self { hash }
    }

    #[must_use]
    pub fn hash(&self) -> &[u8] {
        self.hash.data()
    }
}

#[derive(Clone)]
pub struct PrivateKey {
    private_key: Vec,
}

impl PrivateKey {
    #[must_use]
    pub fn new(private_key: Vec) -> Self {
        Self { private_key }
    }

    #[must_use]
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
    #[must_use]
    pub fn new(client_id: Password, client_secret: Password) -> Self {
        Self {
            client_id,
            client_secret,
        }
    }

    #[must_use]
    pub fn client_id(&self) -> &[u8] {
        self.client_id.password()
    }

    #[must_use]
    pub fn client_secret(&self) -> &[u8] {
        self.client_secret.password()
    }
}
