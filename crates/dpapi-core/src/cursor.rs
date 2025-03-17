//! This crate contains split implementation of a [`ReadCursor`] and [`WriteCursor`].

/// ReadCursor is a wrapper around `&mut [u8]` and its purpose is to:
///
/// * Provide convenient methods such as [read_u8][`ReadCursor::read_u8`], [read_u16][`ReadCursor::read_u16`], etc.
/// * Guarantee syscall-free, infallible read access to a continuous slice of memory.
/// * Keep track of the number of bytes read.
/// * Allow peeking into the buffer without moving the internal pointer.
/// * Be `no-std` and `no-alloc` friendly, which [`std::io::Cursor`] is not as of today.
#[derive(Debug)]
pub struct ReadCursor<'a> {
    inner: &'a [u8],
    pos: usize,
}

impl<'a> ReadCursor<'a> {
    /// Creates a new cursor wrapping the provided underlying in-memory buffer.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { inner: bytes, pos: 0 }
    }

    /// Returns the size of the remaining bytes.
    pub fn len(&self) -> usize {
        self.inner.len() - self.pos
    }

    /// Returns `true` if there are no bytes left.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether cursor reached `EOF`.
    ///
    /// Uses `is_empty` under the hood.
    pub fn eof(&self) -> bool {
        self.is_empty()
    }

    /// Returns the remaining bytes.
    #[track_caller]
    pub fn remaining(&self) -> &[u8] {
        let idx = core::cmp::min(self.pos, self.inner.len());
        &self.inner[idx..]
    }

    /// Gets a reference to the underlying buffer wrapped by this cursor.
    pub fn inner(&self) -> &[u8] {
        self.inner
    }

    /// Returns the current position in the wrapped buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Reads specified amount of bytes from the underlying in-memory buffer.
    ///
    /// # Panics
    ///
    /// Panics on out-of-bounds access.
    ///
    /// Panics on unsuccessful conversion.
    #[track_caller]
    pub fn read_array<const N: usize>(&mut self) -> [u8; N] {
        let bytes = &self.inner[self.pos..self.pos + N];
        self.pos += N;
        bytes.try_into().expect("N-elements array")
    }

    /// Reads specified amount of bytes from the underlying in-memory buffer.
    ///
    /// # Panics
    ///
    /// Panics on out-of-bounds access.
    #[track_caller]
    pub fn read_slice(&mut self, n: usize) -> &'a [u8] {
        let bytes = &self.inner[self.pos..self.pos + n];
        self.pos += n;
        bytes
    }

    /// Reads the remaining of the underlying in-memory buffer.
    #[track_caller]
    pub fn read_remaining(&mut self) -> &'a [u8] {
        self.read_slice(self.len())
    }

    /// Reads 8-bits unsigned integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_u8(&mut self) -> u8 {
        u8::from_le_bytes(self.read_array::<1>())
    }

    /// Reads 16-bits LE-encoded unsigned integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_u16(&mut self) -> u16 {
        u16::from_le_bytes(self.read_array::<2>())
    }

    /// Reads 32-bits LE-encoded unsigned integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.read_array::<4>())
    }

    /// Reads 64-bits LE-encoded unsigned integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.read_array::<8>())
    }

    /// Reads 8-bits BE-encoded integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_i8(&mut self) -> i8 {
        i8::from_le_bytes(self.read_array::<1>())
    }

    /// Reads 16-bits LE-encoded integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_i16(&mut self) -> i16 {
        i16::from_le_bytes(self.read_array::<2>())
    }

    /// Reads 32-bits LE-encoded integer from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_i32(&mut self) -> i32 {
        i32::from_le_bytes(self.read_array::<4>())
    }

    /// Reads 64-bits LE-encoded float from the underlying in-memory buffer.
    #[track_caller]
    pub fn read_f64(&mut self) -> f64 {
        f64::from_le_bytes(self.read_array::<8>())
    }

    /// Gets `N` elements from the underlying in-memory buffer. Does not update the internal pointer.
    ///
    /// # Panics
    ///
    /// Panics on out-of-bounds access.
    ///
    /// Panics on unsuccessful conversion.
    #[track_caller]
    pub fn peek<const N: usize>(&mut self) -> [u8; N] {
        self.inner[self.pos..self.pos + N].try_into().expect("N-elements array")
    }

    /// Gets 8-bits unsigned integer from the underlying in-memory buffer. Does not update the internal pointer.
    #[track_caller]
    pub fn peek_u8(&mut self) -> u8 {
        u8::from_le_bytes(self.peek::<1>())
    }

    /// Gets 16-bits LE-encoded unsigned integer from the underlying in-memory buffer. Does not update the internal pointer.
    #[track_caller]
    pub fn peek_u16(&mut self) -> u16 {
        u16::from_le_bytes(self.peek::<2>())
    }

    /// Gets 32-bits LE-encoded unsigned integer from the underlying in-memory buffer. Does not update the internal pointer.
    #[track_caller]
    pub fn peek_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.peek::<4>())
    }

    /// Advances the pointer of the cursor on a given `len`.
    pub fn advance(&mut self, len: usize) {
        self.pos += len;
    }
}

/// WriteCursor is a wrapper around `&mut [u8]` and its purpose is to:
///
/// * Provide convenient methods such as [write_u8][`WriteCursor::write_u8`], [write_u16][`WriteCursor::write_u16`], etc.
/// * Guarantee syscall-free, infallible write access to a continuous slice of memory.
/// * Keep track of the number of bytes written.
/// * Allow backtracking to override a value previously written or skipped.
/// * Be `no-std` and `no-alloc` friendly, which [`std::io::Cursor`] is not as of today.
#[derive(Debug)]
pub struct WriteCursor<'a> {
    inner: &'a mut [u8],
    pos: usize,
}

impl<'a> WriteCursor<'a> {
    /// Creates a new cursor wrapping the provided the underlying in-memory buffer.
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { inner: bytes, pos: 0 }
    }

    /// Returns the size of the remaining bytes.
    pub fn len(&self) -> usize {
        self.inner.len() - self.pos
    }

    /// Returns `true` if there are no bytes left.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether cursor reached EOF.
    ///
    /// Uses `is_empty` under the hood.
    pub fn eof(&self) -> bool {
        self.is_empty()
    }

    /// Returns the remaining bytes.
    #[track_caller]
    pub fn remaining(&self) -> &[u8] {
        &self.inner[self.pos..]
    }

    /// Returns the remaining bytes as a mutable reference.
    #[track_caller]
    pub fn remaining_mut(&mut self) -> &mut [u8] {
        &mut self.inner[self.pos..]
    }

    /// Gets a reference to the underlying buffer wrapped by this cursor.
    pub fn inner(&self) -> &[u8] {
        self.inner
    }

    /// Gets a reference to the underlying buffer wrapped by this cursor as a mutable reference.
    pub fn inner_mut(&mut self) -> &mut [u8] {
        self.inner
    }

    /// Returns the current position in the wrapped buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Writes a given array into the underlying in-memory buffer.
    ///
    /// # Panics
    ///
    /// Panics on out-of-bounds access.
    #[track_caller]
    pub fn write_array<const N: usize>(&mut self, array: &[u8; N]) {
        self.inner[self.pos..self.pos + N].copy_from_slice(array);
        self.pos += N;
    }

    /// Writes a given slice of bytes into the underlying in-memory buffer.
    ///
    /// # Panics
    ///
    /// Panics on out-of-bounds access.
    #[track_caller]
    pub fn write_slice(&mut self, slice: &[u8]) {
        let n = slice.len();
        self.inner[self.pos..self.pos + n].copy_from_slice(slice);
        self.pos += n;
    }

    /// Writes 8-bits unsigned integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_u8(&mut self, value: u8) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 16-bits LE-encoded unsigned integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_u16(&mut self, value: u16) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 32-bits LE-encoded unsigned integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_u32(&mut self, value: u32) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 64-bits LE-encoded unsigned integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_u64(&mut self, value: u64) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 8-bits LE-encoded integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_i8(&mut self, value: i8) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 16-bits LE-encoded integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_i16(&mut self, value: i16) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 32-bits LE-encoded integer into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_i32(&mut self, value: i32) {
        self.write_array(&value.to_le_bytes())
    }

    /// Writes 64-bits LE-encoded float into the underlying in-memory buffer.
    #[track_caller]
    pub fn write_f64(&mut self, value: f64) {
        self.write_array(&value.to_le_bytes())
    }

    /// Advances the pointer of the cursor on a given `len`.
    pub fn advance(&mut self, len: usize) {
        self.pos += len;
    }
}
