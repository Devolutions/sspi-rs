#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use uuid::Uuid;
use winscard::{Cache, Error, ErrorKind, WinScardResult};

/// A single smart card cache item.
struct CacheItem {
    /// Revision of the card data this value has been captured at.
    ///
    /// See the `FreshnessCounter` parameter of the [SCardReadCacheW] function.
    ///
    /// [SCardReadCacheW]: https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardreadcachew
    freshness_counter: u32,
    value: Vec<u8>,
}

#[derive(Default)]
struct ScardCache {
    /// Cache items of every known smart card.
    ///
    /// The `SCardReadCache`/`SCardWriteCache` functions scope the items by the card identifier and
    /// the lookup name, so the items of one card never shadow the items of another one.
    cards: BTreeMap<Uuid, BTreeMap<String, CacheItem>>,
}

impl ScardCache {
    fn read(&mut self, card_id: Uuid, freshness_counter: u32, key: &str) -> WinScardResult<Vec<u8>> {
        let item = self.cards.get(&card_id).and_then(|items| items.get(key));

        let Some(item) = item else {
            return Err(Error::new(
                ErrorKind::CacheItemNotFound,
                format!("Cache item '{key}' of the card {card_id} not found"),
            ));
        };
        let cached_freshness_counter = item.freshness_counter;

        if cached_freshness_counter >= freshness_counter {
            return Ok(item.value.clone());
        }

        // The card has been changed since this item was cached. Stale items must be deleted from
        // the cache and not only reported.
        self.remove(card_id, key);

        Err(Error::new(
            ErrorKind::CacheItemStale,
            format!(
                "Cache item '{key}' of the card {card_id} is stale: cached {cached_freshness_counter}, requested {freshness_counter}"
            ),
        ))
    }

    fn write(&mut self, card_id: Uuid, freshness_counter: u32, key: String, value: Vec<u8>) {
        // The YubiKey Smart Card Minidriver deletes a cache item by writing a NULL data buffer.
        if value.is_empty() {
            self.remove(card_id, &key);
        } else {
            self.cards.entry(card_id).or_default().insert(
                key,
                CacheItem {
                    freshness_counter,
                    value,
                },
            );
        }
    }

    fn remove(&mut self, card_id: Uuid, key: &str) {
        if let Some(items) = self.cards.get_mut(&card_id) {
            items.remove(key);
        }
    }
}

/// Emulated `Smart Card Resource Manager` cache.
///
/// pcsc-lite and the PC/SC framework do not have functions for the cache reading/writing, and our
/// emulated smart card has no cache at all, so we emulate the cache by ourselves. The Windows one
/// is global and shared by every established resource manager context, so ours has to be shared as
/// well: items written using one context must be visible to all the others.
static SCARD_CACHE: LazyLock<Mutex<ScardCache>> = LazyLock::new(|| Mutex::new(ScardCache::default()));

fn scard_cache() -> MutexGuard<'static, ScardCache> {
    SCARD_CACHE.lock().expect("scard cache mutex locking should not fail")
}

/// Reads the cache item value of the specified smart card.
pub(super) fn read(card_id: Uuid, freshness_counter: u32, key: &str) -> WinScardResult<Vec<u8>> {
    scard_cache().read(card_id, freshness_counter, key)
}

/// Writes the cache item value of the specified smart card.
pub(super) fn write(card_id: Uuid, freshness_counter: u32, key: String, value: Vec<u8>) {
    scard_cache().write(card_id, freshness_counter, key, value)
}

/// [Cache] implementation backed by the global [SCARD_CACHE].
///
/// It is used by the emulated smart card context. The system-provided smart card context uses the
/// same global cache via the functions above.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct GlobalScardCache;

impl Cache for GlobalScardCache {
    fn read(&self, card_id: Uuid, freshness_counter: u32, key: &str) -> WinScardResult<Vec<u8>> {
        read(card_id, freshness_counter, key)
    }

    fn write(&mut self, card_id: Uuid, freshness_counter: u32, key: String, value: Vec<u8>) {
        write(card_id, freshness_counter, key, value)
    }
}
