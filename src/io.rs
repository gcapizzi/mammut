pub trait Display {
    fn url(&self, s: &url::Url);
}

pub struct TerminalDisplay {}

impl TerminalDisplay {
    pub fn new() -> TerminalDisplay {
        TerminalDisplay {}
    }
}

impl Display for TerminalDisplay {
    fn url(&self, url: &url::Url) {
        println!("{}", url);
    }
}
