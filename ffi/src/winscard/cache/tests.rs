use super::*;

/// The [ScardCache] tests use isolated cache instances, so one card identifier is enough.
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
// way the smart card contexts do. Tests run in parallel and share that cache, so each one must
// use its own card identifiers.
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
