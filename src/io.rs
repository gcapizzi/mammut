pub trait UserInterface {
    fn println(&self, s: &str);
}

pub struct Console {}

impl Console {
    pub fn new() -> Console {
        Console {}
    }
}

impl UserInterface for Console {
    fn println(&self, s: &str) {
        println!("{}", s);
    }
}
