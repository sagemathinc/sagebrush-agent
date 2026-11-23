//! Secrets (contract §7): one owner type, zero-initialized before any read, zeroed in Drop, never cloned or printed.

/// A credential or an environment entry holding one. The buffer is fully initialized (zeros) from the start, so reads
/// never touch uninitialized memory; `len` is how much of it is in use.
pub struct Secret {
    buf: Vec<u8>,
    len: usize,
}

impl Secret {
    /// A zeroed buffer of exactly `cap` bytes, allocated once (no later reallocation: every write is bounded by it).
    pub fn zeroed(cap: usize) -> Secret {
        Secret { buf: vec![0u8; cap], len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// The initialized, unused tail, for a read to fill.
    pub fn spare(&mut self) -> &mut [u8] {
        let l = self.len;
        &mut self.buf[l..]
    }

    /// Mark `n` more bytes (just written into `spare()`) as in use.
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.buf.len() - self.len);
        self.len += n;
    }

    /// Append bytes; false (nothing appended) if they don't fit the fixed capacity.
    pub fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.buf.len() - self.len {
            return false;
        }
        let l = self.len;
        self.buf[l..l + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        true
    }

    /// A pointer to the in-use bytes (for execve's envp, built just before the call); the buffer must hold a NUL.
    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }
}

#[allow(unsafe_code)]
impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.buf.iter_mut() {
            // SAFETY (contract §6, non-syscall conversion 3): `b` is a valid, aligned, exclusive reference into the
            // buffer; a volatile write keeps the compiler from eliding the zeroing of memory about to be freed.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        self.len = 0;
        // Debug builds only (compiled out of release): lets tests/cli.rs prove a panic still zeroed every Secret.
        #[cfg(debug_assertions)]
        if let Some(log) = std::env::var_os("SAGEBRUSH_LAUNCH_TEST_DROPLOG") {
            use std::io::Write;
            let zeroed = self.buf.iter().all(|&b| b == 0);
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(log) {
                let _ = writeln!(f, "dropped zeroed={zeroed} cap={}", self.buf.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_and_zero_initialized() {
        let mut s = Secret::zeroed(8);
        assert!(s.spare().iter().all(|&b| b == 0));
        s.spare()[..3].copy_from_slice(b"abc");
        s.advance(3);
        assert_eq!(s.as_bytes(), b"abc");
        assert!(s.push(b"de"));
        assert!(!s.push(b"overflow"), "never grows past its fixed capacity");
        assert_eq!(s.as_bytes(), b"abcde");
    }
}
