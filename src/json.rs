use crate::prelude::*;

pub trait DeserializeJsonWithPath {
    fn json_with_path<T: serde::de::DeserializeOwned>(self) -> Result<T>;
}

impl DeserializeJsonWithPath for String {
    fn json_with_path<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let jd = &mut serde_json::Deserializer::from_str(&self);
        serde_path_to_error::deserialize(jd)
            .map_err(|source| Error::JSON { source })
    }
}

impl DeserializeJsonWithPath for reqwest::blocking::Response {
    fn json_with_path<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let bytes =
            self.bytes().map_err(|source| Error::Reqwest { source })?;
        let jd = &mut serde_json::Deserializer::from_slice(&bytes);
        serde_path_to_error::deserialize(jd)
            .map_err(|source| Error::JSON { source })
    }
}

#[async_trait::async_trait]
pub trait DeserializeJsonWithPathAsync {
    async fn json_with_path<T: serde::de::DeserializeOwned>(
        self,
    ) -> Result<T>;
}

#[async_trait::async_trait]
impl DeserializeJsonWithPathAsync for reqwest::Response {
    async fn json_with_path<T: serde::de::DeserializeOwned>(
        self,
    ) -> Result<T> {
        let bytes = self
            .bytes()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        let jd = &mut serde_json::Deserializer::from_slice(&bytes);
        serde_path_to_error::deserialize(jd)
            .map_err(|source| Error::JSON { source })
    }
}
