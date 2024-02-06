use crate::client::menu::{connection_info};

mod client;
mod models;
mod server;
mod format;

fn main() {
    if connection_info().is_ok() {}
}
