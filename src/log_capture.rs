//! Test support for checking that secrets stay out of the logs.
//!
//! A test starts a [`LogCapture`], runs the code under test, and calls [`LogCapture::assert_no_secrets`].
//! The capture is scoped to the test's thread, so parallel tests do not see each other's logs or secrets.
//! Code that runs on other threads is not captured.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use tracing::Level;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::format::FmtSpan;

/// Named secrets: the name goes into the failure message.
type NamedSecrets = Vec<(&'static str, Vec<u8>)>;

thread_local! {
    /// The secrets of the capture running on this thread, or `None` when no capture is running.
    static SECRETS: RefCell<Option<NamedSecrets>> = const { RefCell::new(None) };
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Collects the logs of the current thread until it is dropped.
///
/// The collected text includes the fields recorded by every span when it is created,
/// because a secret recorded as a span field is printed at that moment.
pub struct LogCapture {
    buffer: Buffer,
    _guard: DefaultGuard,
}

impl LogCapture {
    /// Starts collecting the events and spans up to `max_level` of the current thread.
    ///
    /// A thread runs one capture at a time.
    pub fn start(max_level: Level) -> Self {
        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(max_level)
            .with_span_events(FmtSpan::NEW)
            .with_ansi(false)
            .with_writer({
                let buffer = buffer.clone();
                move || buffer.clone()
            })
            .finish();

        SECRETS.with_borrow_mut(|secrets| {
            assert!(secrets.is_none(), "a capture is already running on this thread");
            *secrets = Some(Vec::new());
        });

        Self {
            buffer,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// Registers a secret that the code under test must not log.
    ///
    /// The secret has to come from the test itself or from a party the test reads it back from,
    /// so that the expected value does not depend on the logging code.
    /// It may be recorded from any code running on the capturing thread.
    /// Does nothing when no capture is running, so shared test helpers can record unconditionally.
    pub fn record_secret(name: &'static str, secret: &[u8]) {
        SECRETS.with_borrow_mut(|secrets| {
            if let Some(secrets) = secrets {
                secrets.push((name, secret.to_vec()));
            }
        });
    }

    /// Returns everything collected so far.
    pub fn output(&self) -> String {
        String::from_utf8(self.buffer.0.lock().unwrap().clone()).unwrap()
    }

    /// Returns the number of the secrets recorded since the capture started.
    pub fn recorded_secrets(&self) -> usize {
        SECRETS.with_borrow(|secrets| secrets.as_ref().map_or(0, Vec::len))
    }

    /// Asserts that something was logged and that none of the recorded secrets is in the output.
    ///
    /// Each secret is searched for as a comma-separated list of decimal bytes, as lower and upper case hex,
    /// and, when it is valid UTF-8, as text and as UTF-16LE in these forms.
    pub fn assert_no_secrets(self) {
        let output = self.output();
        assert!(!output.is_empty(), "the capture collected no logs");

        SECRETS.with_borrow(|secrets| {
            for (name, secret) in secrets.iter().flatten() {
                // A short secret could match unrelated log text by chance.
                assert!(secret.len() >= 8, "the {name} is too short to be searched for");

                for rendered in renderings(secret) {
                    assert!(!output.contains(&rendered), "the logs contain the {name}: {rendered}");
                }
            }
        });
    }
}

impl Drop for LogCapture {
    fn drop(&mut self) {
        SECRETS.with_borrow_mut(|secrets| *secrets = None);
    }
}

fn renderings(secret: &[u8]) -> Vec<String> {
    let mut renderings = bytes_renderings(secret);

    if let Ok(text) = std::str::from_utf8(secret) {
        renderings.push(text.to_owned());
        renderings.push(format!("{text:?}"));

        let utf16_le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        renderings.extend(bytes_renderings(&utf16_le));
    }

    renderings
}

/// The list rendering has no brackets because the secret is usually printed inside a longer byte string.
fn bytes_renderings(bytes: &[u8]) -> Vec<String> {
    let mut hex_lower = String::new();
    let mut hex_upper = String::new();
    for byte in bytes {
        write!(hex_lower, "{byte:02x}").unwrap();
        write!(hex_upper, "{byte:02X}").unwrap();
    }
    let list = bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");

    vec![list, hex_lower, hex_upper]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "p4ssw0rd-9f2c";

    #[test]
    #[should_panic(expected = "the logs contain the password")]
    fn detects_secret_logged_as_utf8_text() {
        let capture = LogCapture::start(Level::DEBUG);
        LogCapture::record_secret("password", PASSWORD.as_bytes());

        tracing::debug!(password = PASSWORD, "Authenticating");

        capture.assert_no_secrets();
    }

    #[test]
    #[should_panic(expected = "the logs contain the password")]
    fn detects_secret_logged_as_utf16_bytes() {
        let capture = LogCapture::start(Level::DEBUG);
        LogCapture::record_secret("password", PASSWORD.as_bytes());

        let utf16: Vec<u8> = PASSWORD.encode_utf16().flat_map(u16::to_le_bytes).collect();
        tracing::debug!(?utf16, "Authenticating");

        capture.assert_no_secrets();
    }

    #[test]
    fn accepts_logs_without_the_secret() {
        let capture = LogCapture::start(Level::DEBUG);
        LogCapture::record_secret("password", PASSWORD.as_bytes());

        tracing::debug!("Authenticating");

        capture.assert_no_secrets();
    }
}
