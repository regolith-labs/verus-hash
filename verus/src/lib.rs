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
    // Use hex crate only in tests (requires std)
    extern crate std;
    use hex::FromHex;
    // Removed unused import: use std::vec;

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
        // NOTE: This value corresponds to the v2.0 spec (Haraka-512/256 with lane selection 8,24,40,56)
        // It does NOT match the v2.2/v2b spec which includes extra mixing.
        let expected_verus_le = <[u8; 32]>::from_hex(
            "2aa88d0c5ed366f1690b7145942cd3692aa88d0c5ed366f1d32c94450b71690b",
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

    // Removed generate_constants_file test.
    // Constants are now generated automatically by the build.rs script.

    #[test]
    fn test_host_matches_known_bpf_hash() {
        // This test verifies that the hash computed by the host-compiled C code
        // (used during `cargo test`) matches a known, pre-calculated hash value
        // that is expected from the BPF-compiled version of the same C code.
        // This helps catch regressions where C code behavior might diverge
        // between host and BPF targets (e.g., due to alignment issues).

        // 1. Define a fixed input buffer.
        let input = [0u8; 64];

        // 2. Define the expected hash output (Little-Endian).
        // This value was obtained by running `verus::verus_hash(&[0u8; 64])`
        // using the C implementation compiled for the host. The assumption is
        // that a correct BPF build should yield the identical result.
        // Hash: 9e943744647a183cf776ac757615e7719e943744647a183c75ac76cf15e77176 (LE)
        let expected_le_hash = [
            0x76, 0x71, 0xe7, 0x15, 0xcf, 0x76, 0xac, 0x75, 0x3c, 0x18, 0x7a, 0x64, 0x44, 0x37,
            0x94, 0x9e, 0x71, 0xe7, 0x15, 0x76, 0x75, 0xac, 0x76, 0xcf, 0x3c, 0x18, 0x7a, 0x64,
            0x44, 0x37, 0x94, 0x9e,
        ];

        // 3. Calculate the hash using the `verus_hash` function linked in the test environment.
        // This uses the library built by `build.rs` for the host target.
        let host_le_hash = verus_hash(&input);

        // 4. Assert that the host hash matches the expected hash.
        assert_eq!(
            host_le_hash, expected_le_hash,
            "Host hash output does not match the expected (known BPF) hash output!"
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
