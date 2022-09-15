pub trait Cache<T> {
    fn set(&self, key: &str, value: &T) -> Result<(), anyhow::Error>;
    fn get(&self, key: &str) -> Result<T, anyhow::Error>;
}

pub struct XDG {
    prefix: String,
}

impl XDG {
    pub fn new(prefix: String) -> XDG {
        XDG { prefix }
    }
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> Cache<T> for XDG {
    fn get(&self, key: &str) -> Result<T, anyhow::Error> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.get_cache_file(key);
        let value_file = std::fs::File::open(path)?;
        Ok(serde_json::from_reader(&value_file)?)
    }

    fn set(&self, key: &str, value: &T) -> Result<(), anyhow::Error> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.place_cache_file(key)?;
        let value_file = std::fs::File::create(path)?;
        serde_json::to_writer(&value_file, &value)?;
        Ok(())
    }
}
