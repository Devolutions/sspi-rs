use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

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
    items: BTreeMap<String, CacheItem>,
}

impl ScardCache {
    fn read(&mut self, key: &str, freshness_counter: u32) -> WinScardResult<Vec<u8>> {
        let Some(item) = self.items.get(key) else {
            return Err(Error::new(
                ErrorKind::CacheItemNotFound,
                format!("Cache item '{key}' not found"),
            ));
        };
        let cached_freshness_counter = item.freshness_counter;

        if cached_freshness_counter >= freshness_counter {
            return Ok(item.value.clone());
        }

        // The card has been changed since this item was cached. Stale items must be deleted from
        // the cache and not only reported.
        self.items.remove(key);

        Err(Error::new(
            ErrorKind::CacheItemStale,
            format!("Cache item '{key}' is stale: cached {cached_freshness_counter}, requested {freshness_counter}"),
        ))
    }

    fn write(&mut self, key: String, freshness_counter: u32, value: Vec<u8>) {
        // The YubiKey Smart Card Minidriver deletes a cache item by writing a NULL data buffer.
        if value.is_empty() {
            self.items.remove(&key);
        } else {
            self.items.insert(
                key,
                CacheItem {
                    freshness_counter,
                    value,
                },
            );
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

/// Reads the cache item value.
pub(super) fn read(key: &str, freshness_counter: u32) -> WinScardResult<Vec<u8>> {
    scard_cache().read(key, freshness_counter)
}

/// Writes the cache item value.
pub(super) fn write(key: String, freshness_counter: u32, value: Vec<u8>) {
    scard_cache().write(key, freshness_counter, value)
}

/// [Cache] implementation backed by the global [SCARD_CACHE].
///
/// It is used by the emulated smart card context. The system-provided smart card context uses the
/// same global cache via the functions above.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct GlobalScardCache;

impl Cache for GlobalScardCache {
    fn read(&self, key: &str, freshness_counter: u32) -> WinScardResult<Vec<u8>> {
        read(key, freshness_counter)
    }

    fn write(&mut self, key: String, freshness_counter: u32, value: Vec<u8>) {
        write(key, freshness_counter, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_returns_not_found_for_missing_item() {
        let mut cache = ScardCache::default();

        let err = cache.read("cmapfile", 1).unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn read_returns_value_when_cached_revision_is_not_older() {
        let mut cache = ScardCache::default();
        cache.write("cmapfile".to_owned(), 2, vec![1, 2, 3]);

        assert_eq!(cache.read("cmapfile", 1).unwrap(), vec![1, 2, 3]);
        assert_eq!(cache.read("cmapfile", 2).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn read_evicts_item_with_older_cached_revision() {
        let mut cache = ScardCache::default();
        cache.write("cmapfile".to_owned(), 1, vec![1, 2, 3]);

        let err = cache.read("cmapfile", 2).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemStale));

        // The stale item must be deleted and not only reported.
        let err = cache.read("cmapfile", 2).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn write_overwrites_item_regardless_of_revision() {
        let mut cache = ScardCache::default();
        cache.write("cmapfile".to_owned(), 5, vec![1, 2, 3]);
        cache.write("cmapfile".to_owned(), 2, vec![4, 5, 6]);

        assert_eq!(cache.read("cmapfile", 2).unwrap(), vec![4, 5, 6]);
    }

    #[test]
    fn write_with_empty_value_deletes_item() {
        let mut cache = ScardCache::default();
        cache.write("cmapfile".to_owned(), 1, vec![1, 2, 3]);
        cache.write("cmapfile".to_owned(), 1, Vec::new());

        let err = cache.read("cmapfile", 1).unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn items_written_with_max_revision_never_become_stale() {
        let mut cache = ScardCache::default();
        // This is how the emulated smart card writes the items that describe itself.
        cache.write("cmapfile".to_owned(), u32::MAX, vec![1, 2, 3]);

        assert_eq!(cache.read("cmapfile", u32::MAX).unwrap(), vec![1, 2, 3]);
    }

    // The tests below exercise the process-global cache via the [Cache] implementation, the same
    // way the smart card contexts do.
    //
    // The test harness runs tests in parallel threads of the same process, and all of them share
    // the one global cache. So, every test must use its own unique cache keys.
    fn key(test_name: &str) -> String {
        format!("test/{test_name}/cmapfile")
    }

    #[test]
    fn global_cache_read_returns_written_value() {
        let mut cache = GlobalScardCache;
        let key = key("global_cache_read_returns_written_value");
        let value = (0..=u8::MAX).collect::<Vec<_>>();

        cache.write(key.clone(), 3, value.clone());

        assert_eq!(cache.read(&key, 3).unwrap(), value);
    }

    #[test]
    fn global_cache_read_returns_not_found_for_missing_item() {
        let cache = GlobalScardCache;

        let err = cache
            .read(&key("global_cache_read_returns_not_found_for_missing_item"), 1)
            .unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_write_with_empty_value_deletes_item() {
        let mut cache = GlobalScardCache;
        let key = key("global_cache_write_with_empty_value_deletes_item");

        cache.write(key.clone(), 1, vec![1, 2, 3]);
        assert_eq!(cache.read(&key, 1).unwrap(), vec![1, 2, 3]);

        cache.write(key.clone(), 1, Vec::new());

        let err = cache.read(&key, 1).unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_read_honours_freshness_counter() {
        let mut cache = GlobalScardCache;
        let key = key("global_cache_read_honours_freshness_counter");

        cache.write(key.clone(), 2, vec![1, 2, 3]);

        // The cached item is not older than the requested revision: it is still valid.
        assert_eq!(cache.read(&key, 1).unwrap(), vec![1, 2, 3]);
        assert_eq!(cache.read(&key, 2).unwrap(), vec![1, 2, 3]);

        // The caller has a newer card revision than the cached item: the item is stale
        // and must be deleted from the cache.
        let err = cache.read(&key, 3).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemStale));

        let err = cache.read(&key, 3).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_write_overwrites_item_with_any_freshness_counter() {
        let mut cache = GlobalScardCache;
        let key = key("global_cache_write_overwrites_item_with_any_freshness_counter");

        cache.write(key.clone(), 5, vec![1, 2, 3]);
        // The item revision can go down: the caller always knows better than the cache.
        cache.write(key.clone(), 2, vec![4, 5, 6]);

        assert_eq!(cache.read(&key, 2).unwrap(), vec![4, 5, 6]);

        // The item carries the revision it has been written with.
        let err = cache.read(&key, 3).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemStale));
    }

    #[test]
    fn global_cache_is_shared_between_smart_card_contexts() {
        let mut one_context_cache = GlobalScardCache;
        let another_context_cache = GlobalScardCache;
        let key = key("global_cache_is_shared_between_smart_card_contexts");

        one_context_cache.write(key.clone(), 1, vec![1, 2, 3]);

        // The Windows smart card cache is global: the items written using one resource manager
        // context must be visible in all the others.
        assert_eq!(another_context_cache.read(&key, 1).unwrap(), vec![1, 2, 3]);
    }
}
