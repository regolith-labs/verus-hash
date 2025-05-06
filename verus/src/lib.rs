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
        // void verus_hash_v2(void *result, const void *data, size_t len)
        // or similar, resulting in a 32-byte hash.
        fn verus_hash_v2(out_ptr: *mut u8, in_ptr: *const u8, len: usize);

        // Expose the static round constant array from the C code.
        // Its actual name in haraka_portable.c is `rc`.
        static rc: [u8; 40 * 16]; // 640 bytes total

        // Initialization function (`verus_hash_v2_init`) is no longer needed.
        // Constants are baked into the static library at compile time via
        // the included `haraka_rc_vrsc.inc` file for both host and SBF builds.
    }

    // No runtime initialization needed anymore.

    /// Compute the little-endian VerusHash 2.0 of `data` using the C backend.
    pub fn verus_hash(data: &[u8]) -> [u8; 32] {
        // Constants are baked in, no runtime initialization required.
        let mut out = [0u8; 32];
        // Call the FFI function. It's unsafe because it involves FFI.
        // Safety relies on the C implementation being correct.
        unsafe { verus_hash_v2(out.as_mut_ptr(), data.as_ptr(), data.len()) };
        out
    }

    /// Borrows the static Haraka round constant table (read-only).
    /// The symbol name in C is `rc`.
    pub fn haraka_rc() -> &'static [u8; 640] {
        // Safety: Accessing a static C variable. Assumes the C library
        // correctly defines and links `rc` as a constant array of the expected size.
        unsafe { &rc }
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

// Re-export the verus_hash function and the constants accessor from the backend module.
pub use backend::haraka_rc;
pub use backend::verus_hash; // Export the new function

// --- FFI Helper for Constant Generation (Host Only) ---
// Removed: Constants are now generated during the build process by build.rs

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
    extern crate std;

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

    // Removed generate_constants_file test.
    // Constants are now generated automatically by the build.rs script.

    // ─────────────────────────────────────────────────────────────────────────────
    //  NEW: multi-variant golden-vector tests
    //  Input buffer = "Test1234" * 12  (96 bytes)
    // ─────────────────────────────────────────────────────────────────────────────
    const TEST_96: &[u8] = b"Test1234Test1234Test1234Test1234\
                             Test1234Test1234Test1234Test1234\
                             Test1234Test1234Test1234Test1234";

    const VH1_LE: [u8; 32] = hex_literal::hex!(
        "84 11 15 f4 db 8a c9 a8 35 1f b2 25 37 bd 63 fa \
         cc dd 42 20 e6 09 4a f1 06 d7 9b 56 e6 09 d7 2c"
    );
    const VH2_LE: [u8; 32] = hex_literal::hex!(
        "ed 3d bd 1d 79 83 42 26 4c bf ee 4a 49 56 49 17 \
         ed b6 8b 3a 5c 56 6d 1f 48 70 05 11 3b c4 ce 55"
    );
    const VH2B_LE: [u8; 32] = hex_literal::hex!(
        "ed 3d bd 1d 79 83 42 26 4c bf ee 4a 49 56 49 17 \
         ed b6 8b 3a 5c 56 6d 1f 48 70 05 11 3b c4 ce 55"
    ); // Updated to match C++ V2.2 output (same as V2.0 for this input)
    const VH2B1_LE: [u8; 32] = hex_literal::hex!(
        "ed 3d bd 1d 79 83 42 26 4c bf ee 4a 49 56 49 17 \
         ed b6 8b 3a 5c 56 6d 1f 48 70 05 11 3b c4 ce 55"
    ); // Updated to match C++ V2.1 output (same as V2.0 for this input)

    #[test]
    fn verushash1_golden() {
        // This test should FAIL unless the C code implements VerusHash v1
        let actual_hash = verus_hash(TEST_96);
        assert_eq!(
            actual_hash,
            VH1_LE,
            "Hash does not match VerusHash v1. Expected: {}, Actual: {}",
            hex::encode(VH1_LE),
            hex::encode(actual_hash)
        );
    }

    #[test]
    fn verushash2_golden() {
        // This test should PASS if the C code implements VerusHash v2
        let actual_hash = verus_hash(TEST_96);
        assert_eq!(
            actual_hash,
            VH2_LE,
            "Hash does not match VerusHash v2. Expected: {}, Actual: {}",
            hex::encode(VH2_LE),
            hex::encode(actual_hash)
        );
    }

    #[test]
    fn verushash2b_golden() {
        // This test expects VerusHash v2b.
        // Per C++ reference output for this input, v2b hash is same as v2 hash.
        let actual_hash = verus_hash(TEST_96);
        assert_eq!(
            actual_hash,
            VH2B_LE,
            "Hash does not match VerusHash v2b (expected to be same as v2 for this input). Expected: {}, Actual: {}",
            hex::encode(VH2B_LE),
            hex::encode(actual_hash)
        );
    }

    #[test]
    fn verushash2b1_golden() {
        // This test expects VerusHash v2b1.
        // Per C++ reference output for this input, v2b1 hash is same as v2 hash.
        let actual_hash = verus_hash(TEST_96);
        assert_eq!(
            actual_hash,
            VH2B1_LE,
            "Hash does not match VerusHash v2b1 (expected to be same as v2 for this input). Expected: {}, Actual: {}",
            hex::encode(VH2B1_LE),
            hex::encode(actual_hash)
        );
    }
} // End of tests module

/// Converts a difficulty value into a 32-byte big-endian target.
/// target = floor(2^256 / (difficulty + 1)) approximately, or more simply
/// target = MAX_TARGET >> difficulty
/// where MAX_TARGET is 2^256 - 1 ([0xFF; 32]).
/// Made public for use in tests and client.
pub fn difficulty_to_target(difficulty: u64) -> [u8; 32] {
    if difficulty >= 256 {
        // Difficulty is too high, target is effectively zero.
        return [0u8; 32];
    }

    let mut target = [0xFFu8; 32];

    // Calculate the number of full byte shifts (integer division)
    let byte_shifts = (difficulty / 8) as usize;
    // Calculate the remaining bit shifts
    let bit_shifts = (difficulty % 8) as u8;

    // Apply bit shifts first (working from right-most byte to left-most)
    // This shifts the entire 256-bit value right by `bit_shifts`.
    if bit_shifts > 0 {
        let mut carry = 0u8;
        // Iterate from left (MSB) to right (LSB) of the target array
        for i in 0..32 {
            let current_byte = target[i];
            // Shift the current byte right, and bring in the carry from the left byte's shift-out
            target[i] = (current_byte >> bit_shifts) | carry;
            // Calculate the new carry for the next byte (to the right)
            // These are the bits shifted out from the current byte, positioned correctly.
            carry = current_byte << (8 - bit_shifts); // No need for & 0xFF, u8 handles wrap
        }
    }

    // Apply byte shifts (shifting right, filling with zeros from the left)
    if byte_shifts > 0 {
        // Ensure we don't shift beyond the array bounds
        let shift_limit = 32 - byte_shifts;
        // Shift existing bytes to the right
        for i in (0..shift_limit).rev() {
            target[i + byte_shifts] = target[i];
        }
        // Fill the newly opened space at the left (MSB) with zeros
        for i in 0..byte_shifts {
            target[i] = 0;
        }
    }

    target
}
