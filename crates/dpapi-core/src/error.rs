use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {}

pub type Result<T> = core::result::Result<T, Error>;
