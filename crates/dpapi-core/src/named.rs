/// A type with a static name.
pub trait StaticName {
    /// Name associated to this type.
    const NAME: &'static str;
}
