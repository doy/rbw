use crate::pin::backend::{BackendConfig, PinBackend};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub struct KeyringPinBackend;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyringConfig {}
impl BackendConfig for KeyringConfig {}

impl PinBackend for KeyringPinBackend {
    type Config = KeyringConfig;
    fn retrieve_local_secret(
        &self,
        _: &KeyringConfig,
    ) -> anyhow::Result<crate::locked::Vec> {
        let entry = Entry::new("rbw", crate::dirs::profile().as_str())?;
        let mut entry = entry.get_secret().map(Zeroizing::new)?;
        let mut local_secret = crate::locked::Vec::new();
        local_secret.extend(entry.iter().copied());
        entry.zeroize();
        Ok(local_secret)
    }
    fn store_local_secret(
        &self,
        kek: &crate::locked::Vec,
        _: &KeyringConfig,
    ) -> anyhow::Result<()> {
        let entry = Entry::new("rbw", crate::dirs::profile().as_str())?;
        entry.set_secret(kek.data())?;
        Ok(())
    }

    fn clear_local_secret(&self) -> anyhow::Result<()> {
        let entry = Entry::new("rbw", crate::dirs::profile().as_str())?;
        entry
            .delete_credential()
            .map_err(|_| anyhow::anyhow!("Could not delete credential"))
    }
}
