use alloc::vec::Vec;

use crate::Decode;

/// Bound used by other traits when a context struct is required.
pub trait NeedsContext {
    /// Required context.
    type Context<'ctx>;
}

impl<T: Decode> NeedsContext for Vec<T> {
    type Context<'ctx> = usize;
}
