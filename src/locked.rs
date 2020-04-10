pub struct Vec {
    data: Box<arrayvec::ArrayVec<[u8; 4096]>>,
    _lock: region::LockGuard,
}

impl Default for Vec {
    fn default() -> Self {
        let data = Box::new(arrayvec::ArrayVec::<[_; 4096]>::new());
        let lock = region::lock(data.as_ptr(), data.capacity()).unwrap();
        Self { data, _lock: lock }
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

    pub fn extend(&mut self, it: impl Iterator<Item = u8>) {
        self.data.extend(it);
    }

    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }

    pub fn shred(&mut self) {
        self.data.truncate(0);
        self.data.extend(std::iter::repeat(0));
        self.data.truncate(0);
    }
}

impl Drop for Vec {
    fn drop(&mut self) {
        self.shred();
    }
}

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

pub struct Keys {
    keys: Vec,
}

impl Keys {
    pub fn new(keys: Vec) -> Self {
        Self { keys }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.keys.data()[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.keys.data()[32..64]
    }
}

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
