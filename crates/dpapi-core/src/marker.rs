/// Bound used by other traits when a context struct is required.
pub trait NeedsContext {
    /// Required context.
    type Context<'ctx>;
}
