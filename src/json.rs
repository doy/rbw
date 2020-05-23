use crate::prelude::*;

pub trait DeserializeJsonWithPath {
    fn json_with_path<T: serde::de::DeserializeOwned>(self) -> Result<T>;
}

impl DeserializeJsonWithPath for String {
    fn json_with_path<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let jd = &mut serde_json::Deserializer::from_str(&self);
        serde_path_to_error::deserialize(jd).context(crate::error::JSON)
    }
}

impl DeserializeJsonWithPath for reqwest::blocking::Response {
    fn json_with_path<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().context(crate::error::Reqwest)?;
        let jd = &mut serde_json::Deserializer::from_slice(&bytes);
        serde_path_to_error::deserialize(jd).context(crate::error::JSON)
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
        let bytes = self.bytes().await.context(crate::error::Reqwest)?;
        let jd = &mut serde_json::Deserializer::from_slice(&bytes);
        serde_path_to_error::deserialize(jd).context(crate::error::JSON)
    }
}
