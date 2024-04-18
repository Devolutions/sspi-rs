#![cfg(feature = "scard")]

#[macro_use]
mod macros;

mod card;
mod context;

use std::borrow::Cow;

pub use card::SystemScard;
pub use context::SystemScardContext;
use winscard::WinScardResult;

fn parse_multi_string(buf: &[u8]) -> WinScardResult<Vec<&str>> {
    let res: Result<Vec<&str>, _> = buf
        .split(|&c| c == 0)
        .filter(|v| v.is_empty())
        .map(|v| std::str::from_utf8(v))
        .collect();

    Ok(res?)
}

fn parse_multi_string_owned(buf: &[u8]) -> WinScardResult<Vec<Cow<'static, str>>> {
    Ok(parse_multi_string(buf)?
        .iter()
        .map(|&r| Cow::Owned(r.to_owned()))
        .collect())
}
