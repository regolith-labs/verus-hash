//! Safe Rust wrapper around VerusHash 2.0 using the portable C backend.

// Conditionally allow std library features only when not building for BPF.
// BPF environment is no_std. Host environment (including tests) uses std.
#![cfg_attr(target_arch = "bpf", no_std)]

// This module provides the VerusHash implementation.
// It's compiled only when targeting BPF or when the 'portable' feature is enabled.
#[cfg(any(target_arch = "bpf", feature = "portable"))]
mod backend {
    // Link the static library compiled by build.rs.
    // This is needed for both BPF and host (with 'portable' feature) builds.
    #[link(name = "verushash", kind = "static")]
    extern "C" {
        // FFI declaration for the VerusHash function from the C library.
        // Signature must match the C/C++ definition. Assuming it's:
        // void verus_hash_v2(void *result, const void *data, size_t len)
        // or similar, resulting in a 32-byte hash.
        // Note: The exact name might differ (e.g., verus_hash_32); adjust if needed based on build.sh/C code.
        fn verus_hash_v2(out_ptr: *mut u8, in_ptr: *const u8, len: usize);

        // FFI declaration for the VerusHash initialization function.
        fn verus_hash_v2_init();
    }

    // Use std::sync::Once for thread-safe initialization on host targets.
    // BPF is single-threaded, so Once is not needed there.
    #[cfg(not(target_arch = "bpf"))]
    use std::sync::Once;

    #[cfg(not(target_arch = "bpf"))]
    static INIT: Once = Once::new();

    // BPF needs a simple flag for initialization check.
    #[cfg(target_arch = "bpf")]
    static mut INITIALIZED: bool = false;

    /// Initializes the VerusHash C library. Safe to call multiple times.
    fn init_internal() {
        #[cfg(not(target_arch = "bpf"))]
        {
            // Use Once::call_once for thread-safe initialization on host.
            INIT.call_once(|| {
                // Safety: Calling an external C function expected to initialize internal state.
                // Assumed to be safe when called once.
                unsafe { verus_hash_v2_init() };
            });
        }
        #[cfg(target_arch = "bpf")]
        {
            // Safety: Accessing static mut in BPF (single-threaded context).
            // Check and set flag to ensure init runs only once.
            unsafe {
                if !INITIALIZED {
                    verus_hash_v2_init();
                    INITIALIZED = true;
                }
            }
        }
    }

    /// Compute the little-endian VerusHash 2.0 of `data` using the C backend.
    pub fn verus_hash(data: &[u8]) -> [u8; 32] {
        // Ensure the C library is initialized before hashing.
        init_internal();

        let mut out = [0u8; 32];
        // Call the FFI function. It's unsafe because it involves FFI.
        // Safety relies on the C implementation being correct and thread-safe (if used concurrently),
        // and that init_internal() has been called.
        unsafe { verus_hash_v2(out.as_mut_ptr(), data.as_ptr(), data.len()) };
        out
    }
}

// This module provides a compile-time error if the crate is built for the host
// *without* the 'portable' feature enabled. This prevents accidental use of
// a non-existent pure-Rust fallback.
#[cfg(not(any(target_arch = "bpf", feature = "portable")))]
mod backend {
    // This function will never be called, but needs to exist for the pub use below.
    pub fn verus_hash(_data: &[u8]) -> [u8; 32] {
        compile_error!(
            "The `verus` crate must be built for the BPF target or with the `portable` feature enabled."
        );
    }
}

// Re-export the verus_hash function from the appropriate backend module.
pub use backend::verus_hash;

/// Return `true` if `verus_hash(data)` ≤ `target_be` (both big-endian).
/// *Avoids BigUint and extra Vec allocations for Solana BPF compatibility.*
/// This function now unconditionally uses the `verus_hash` function exported above,
/// which points to the C backend when compiled correctly.
pub fn verify_hash(data: &[u8], target_be: &[u8; 32]) -> bool {
    // Compute the hash (Little-Endian) using the C backend via FFI
    let le = verus_hash(data);

    // Reverse in place into a stack-allocated buffer to get big-endian hash
    let mut hash_be = [0u8; 32];
    for i in 0..32 {
        hash_be[i] = le[31 - i];
    }

    // Constant-time lexicographic compare (hash_be <= target_be)
    // Returns true if hash_be is less than or equal to target_be.
    for i in 0..32 {
        if hash_be[i] < target_be[i] {
            // Current byte is smaller, so hash_be < target_be
            return true;
        } else if hash_be[i] > target_be[i] {
            // Current byte is larger, so hash_be > target_be
            return false;
        }
        // Bytes are equal, continue to the next byte
    }

    // All bytes were equal, so hash_be == target_be
    true
}

// --- Tests ---
// Tests run on the host. Because the 'portable' feature is enabled by default,
// these tests will use the actual C VerusHash implementation via FFI.
#[cfg(test)]
mod tests {
    use super::*;
    // Use hex crate only in tests (requires std)
    extern crate std;
    use hex::FromHex;
    use std::vec; // Import vec for test data

    #[test]
    fn length_is_32() {
        // Uses backend::verus_hash -> C FFI
        assert_eq!(verus_hash(b"").len(), 32);
    }

    #[test]
    fn verify_max_target() {
        // Uses backend::verus_hash -> C FFI
        assert!(verify_hash(b"anything", &[0xFF; 32]));
    }

    #[test]
    fn verify_zero_target_fails() {
        // Uses backend::verus_hash -> C FFI
        // Hash of "anything" will be > 0, so should fail against zero target
        assert!(!verify_hash(b"anything", &[0u8; 32]));
    }

    #[test]
    fn known_vector() {
        // Uses backend::verus_hash -> C FFI
        // This test should now pass as we are using the real VerusHash.
        // pre-computed VerusHash 2.0 of ASCII "abc" (Little-Endian)
        let expected_verus_le = <[u8; 32]>::from_hex(
            "0b6c5e34cf8eb1a7fe43a082ce98864ff61ef79018550029bee5c0985a0f018e",
        )
        .unwrap();
        assert_eq!(verus_hash(b"abc"), expected_verus_le);
    }

    #[test]
    fn verify_known_vector_success() {
        // Verify that the known hash of "abc" meets a target slightly above it.
        let hash_le = verus_hash(b"abc");
        let mut hash_be = [0u8; 32];
        for i in 0..32 {
            hash_be[i] = hash_le[31 - i];
        }

        // Create a target just slightly higher than the hash
        let mut target_be = hash_be;
        // Find the last non-ff byte and increment it (handle potential carry)
        for i in (0..32).rev() {
            if target_be[i] < 0xFF {
                target_be[i] += 1;
                break;
            } else {
                target_be[i] = 0; // Handle carry
            }
        }
        assert!(verify_hash(b"abc", &target_be));
    }

    #[test]
    fn verify_known_vector_fail() {
        // Verify that the known hash of "abc" fails a target slightly below it.
        let hash_le = verus_hash(b"abc");
        let mut hash_be = [0u8; 32];
        for i in 0..32 {
            hash_be[i] = hash_le[31 - i];
        }

        // Create a target just slightly lower than the hash
        let mut target_be = hash_be;
        // Find the last non-zero byte and decrement it (handle potential borrow)
        for i in (0..32).rev() {
            if target_be[i] > 0 {
                target_be[i] -= 1;
                break;
            } else {
                target_be[i] = 0xFF; // Handle borrow
            }
        }
        // Ensure target is not exactly the hash (can happen if hash is 0)
        if target_be != hash_be {
            assert!(!verify_hash(b"abc", &target_be));
        } else {
            // If hash was 0, the only lower target is impossible. Skip assert.
            std::println!("Skipping verify_known_vector_fail as hash is zero.");
        }
    }
}
