use anyhow::{Context, Result};

const CONFIG_KEY: &str = "config";

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Config {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

pub struct XDGStore {
    prefix: String,
}

impl XDGStore {
    pub fn new(prefix: String) -> XDGStore {
        XDGStore { prefix }
    }

    pub fn load(&self) -> Result<Config> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.get_config_file(CONFIG_KEY);
        let config_file = std::fs::File::open(path).context("error loading config")?;
        let config = serde_json::from_reader(&config_file).context("error parsing config")?;
        Ok(config)
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        let path =
            xdg::BaseDirectories::with_prefix(&self.prefix)?.place_config_file(CONFIG_KEY)?;
        let config_file = std::fs::File::create(path).context("error saving config")?;
        serde_json::to_writer(&config_file, config).context("error serializing config")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use expect::{
        expect,
        matchers::{
            equal,
            result::{be_err, be_ok},
        },
    };
    use serial_test::serial;

    #[test]
    #[serial]
    fn when_no_config_is_stored_it_fails() {
        set_tmp_home();
        let store = crate::config::XDGStore::new("foo".to_string());
        let err = store.load();

        expect(&err).to(be_err());
        expect(&format!("{:#}", &err.unwrap_err())).to(equal(
            "error loading config: No such file or directory (os error 2)",
        ));
    }

    #[test]
    #[serial]
    fn it_stores_and_loads_config() {
        set_tmp_home();
        let store = crate::config::XDGStore::new("foo".to_string());

        let config = crate::config::Config {
            base_url: "the/url".to_string(),
            client_id: "client_id".to_string(),
            client_secret: "client_secret".to_string(),
            redirect_url: "the/redirect/url".to_string(),
        };

        expect(&store.save(&config)).to(be_ok());

        let loaded_config = store.load().unwrap();

        expect(&loaded_config).to(equal(config));
    }

    fn set_tmp_home() {
        std::env::set_var(
            "HOME",
            tempfile::tempdir()
                .unwrap()
                .into_path()
                .to_string_lossy()
                .to_string(),
        );
    }
}
