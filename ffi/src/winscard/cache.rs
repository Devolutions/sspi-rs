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

#[cfg(test)]
mod tests {
    use super::*;

    /// Card identifier for the [ScardCache] tests. They construct their own isolated cache
    /// instances, so one identifier is enough.
    fn card_id() -> Uuid {
        Uuid::from_u128(1)
    }

    #[test]
    fn read_returns_not_found_for_missing_item() {
        let mut cache = ScardCache::default();

        let err = cache.read(card_id(), 1, "cmapfile").unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn read_returns_value_when_cached_revision_is_not_older() {
        let mut cache = ScardCache::default();
        cache.write(card_id(), 2, "cmapfile".to_owned(), vec![1, 2, 3]);

        assert_eq!(cache.read(card_id(), 1, "cmapfile").unwrap(), vec![1, 2, 3]);
        assert_eq!(cache.read(card_id(), 2, "cmapfile").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn read_evicts_item_with_older_cached_revision() {
        let mut cache = ScardCache::default();
        cache.write(card_id(), 1, "cmapfile".to_owned(), vec![1, 2, 3]);

        let err = cache.read(card_id(), 2, "cmapfile").unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemStale));

        // The stale item must be deleted and not only reported.
        let err = cache.read(card_id(), 2, "cmapfile").unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn write_overwrites_item_regardless_of_revision() {
        let mut cache = ScardCache::default();
        cache.write(card_id(), 5, "cmapfile".to_owned(), vec![1, 2, 3]);
        cache.write(card_id(), 2, "cmapfile".to_owned(), vec![4, 5, 6]);

        assert_eq!(cache.read(card_id(), 2, "cmapfile").unwrap(), vec![4, 5, 6]);
    }

    #[test]
    fn write_with_empty_value_deletes_item() {
        let mut cache = ScardCache::default();
        cache.write(card_id(), 1, "cmapfile".to_owned(), vec![1, 2, 3]);
        cache.write(card_id(), 1, "cmapfile".to_owned(), Vec::new());

        let err = cache.read(card_id(), 1, "cmapfile").unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn items_written_with_max_revision_never_become_stale() {
        let mut cache = ScardCache::default();
        // This is how the emulated smart card writes the items that describe itself.
        cache.write(card_id(), u32::MAX, "cmapfile".to_owned(), vec![1, 2, 3]);

        assert_eq!(cache.read(card_id(), u32::MAX, "cmapfile").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn items_of_different_cards_do_not_shadow_each_other() {
        let one_card = Uuid::from_u128(1);
        let another_card = Uuid::from_u128(2);

        let mut cache = ScardCache::default();
        cache.write(one_card, 1, "cmapfile".to_owned(), vec![1, 2, 3]);
        cache.write(another_card, 1, "cmapfile".to_owned(), vec![4, 5, 6]);

        assert_eq!(cache.read(one_card, 1, "cmapfile").unwrap(), vec![1, 2, 3]);
        assert_eq!(cache.read(another_card, 1, "cmapfile").unwrap(), vec![4, 5, 6]);
    }

    // The tests below exercise the process-global cache via the [Cache] implementation, the same
    // way the smart card contexts do.
    //
    // The test harness runs tests in parallel threads of the same process, and all of them share
    // the one global cache. So, every test must use its own unique card identifiers.
    fn unique_card_id() -> Uuid {
        Uuid::new_v4()
    }

    const KEY: &str = "cmapfile";

    #[test]
    fn global_cache_read_returns_written_value() {
        let mut cache = GlobalScardCache;
        let card_id = unique_card_id();
        let value = (0..=u8::MAX).collect::<Vec<_>>();

        cache.write(card_id, 3, KEY.to_owned(), value.clone());

        assert_eq!(cache.read(card_id, 3, KEY).unwrap(), value);
    }

    #[test]
    fn global_cache_read_returns_not_found_for_missing_item() {
        let cache = GlobalScardCache;

        let err = cache.read(unique_card_id(), 1, KEY).unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_write_with_empty_value_deletes_item() {
        let mut cache = GlobalScardCache;
        let card_id = unique_card_id();

        cache.write(card_id, 1, KEY.to_owned(), vec![1, 2, 3]);
        assert_eq!(cache.read(card_id, 1, KEY).unwrap(), vec![1, 2, 3]);

        // The smart card minidriver deletes a cache item by writing a NULL data buffer.
        cache.write(card_id, 1, KEY.to_owned(), Vec::new());

        let err = cache.read(card_id, 1, KEY).unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_read_honours_freshness_counter() {
        let mut cache = GlobalScardCache;
        let card_id = unique_card_id();

        cache.write(card_id, 2, KEY.to_owned(), vec![1, 2, 3]);

        // The cached item is not older than the requested revision: it is still valid.
        assert_eq!(cache.read(card_id, 1, KEY).unwrap(), vec![1, 2, 3]);
        assert_eq!(cache.read(card_id, 2, KEY).unwrap(), vec![1, 2, 3]);

        // The caller has a newer card revision than the cached item: the item is stale
        // and must be deleted from the cache.
        let err = cache.read(card_id, 3, KEY).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemStale));

        let err = cache.read(card_id, 3, KEY).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_write_overwrites_item_with_any_freshness_counter() {
        let mut cache = GlobalScardCache;
        let card_id = unique_card_id();

        cache.write(card_id, 5, KEY.to_owned(), vec![1, 2, 3]);
        // The item revision can go down: the caller always knows better than the cache.
        cache.write(card_id, 2, KEY.to_owned(), vec![4, 5, 6]);

        assert_eq!(cache.read(card_id, 2, KEY).unwrap(), vec![4, 5, 6]);

        // The item carries the revision it has been written with.
        let err = cache.read(card_id, 3, KEY).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemStale));
    }

    #[test]
    fn global_cache_is_shared_between_smart_card_contexts() {
        let mut one_context_cache = GlobalScardCache;
        let another_context_cache = GlobalScardCache;
        let card_id = unique_card_id();

        one_context_cache.write(card_id, 1, KEY.to_owned(), vec![1, 2, 3]);

        // The Windows smart card cache is global: the items written using one resource manager
        // context must be visible in all the others.
        assert_eq!(another_context_cache.read(card_id, 1, KEY).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn global_cache_isolates_items_by_card_id() {
        let mut cache = GlobalScardCache;
        let one_card = unique_card_id();
        let another_card = unique_card_id();

        // Both cards use the same lookup name: this is what the standard cache item names like
        // `Cached_GeneralFile/mscp/cmapfile` look like.
        cache.write(one_card, 1, KEY.to_owned(), vec![1, 2, 3]);
        cache.write(another_card, 1, KEY.to_owned(), vec![4, 5, 6]);

        assert_eq!(cache.read(one_card, 1, KEY).unwrap(), vec![1, 2, 3]);
        assert_eq!(cache.read(another_card, 1, KEY).unwrap(), vec![4, 5, 6]);
    }

    #[test]
    fn global_cache_read_misses_for_another_card_id() {
        let mut cache = GlobalScardCache;
        let one_card = unique_card_id();
        let another_card = unique_card_id();

        cache.write(one_card, 1, KEY.to_owned(), vec![1, 2, 3]);

        let err = cache.read(another_card, 1, KEY).unwrap_err();

        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
    }

    #[test]
    fn global_cache_delete_is_scoped_to_card_id() {
        let mut cache = GlobalScardCache;
        let one_card = unique_card_id();
        let another_card = unique_card_id();

        cache.write(one_card, 1, KEY.to_owned(), vec![1, 2, 3]);
        cache.write(another_card, 1, KEY.to_owned(), vec![4, 5, 6]);

        // Deleting the item of one card must not touch the item of another one.
        cache.write(one_card, 1, KEY.to_owned(), Vec::new());

        let err = cache.read(one_card, 1, KEY).unwrap_err();
        assert!(matches!(err.error_kind, ErrorKind::CacheItemNotFound));
        assert_eq!(cache.read(another_card, 1, KEY).unwrap(), vec![4, 5, 6]);
    }
}
