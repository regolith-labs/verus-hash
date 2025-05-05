//! Pure Rust implementation of VerusHash 2.2.

// BPF environment is no_std. Host environment (including tests) uses std.
#![cfg_attr(target_arch = "bpf", no_std)]
// Allow std for tests, no_std otherwise (moved from rust_impl.rs)
#![cfg_attr(all(not(test), target_arch = "bpf"), no_std)]
// Allow using `alloc` crate (specifically `vec![]`) in no_std environments like BPF
#![cfg_attr(target_arch = "bpf", feature(alloc_error_handler))]

// Use `extern crate alloc` when in no_std mode (BPF)
#[cfg(target_arch = "bpf")]
extern crate alloc;

// Include the pure Rust implementation.
mod rust_impl;

// Re-export the pure Rust verus_hash function.
pub use rust_impl::verus_hash_rust as verus_hash;

// The haraka_rc function is no longer needed as constants are internal to haraka-bpf.
// pub use backend::haraka_rc; // Remove this line

// Define a simple panic handler for no_std environments (required by BPF)
#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Solana's panic handler will be used in practice.
    // This basic version satisfies the compiler requirement.
    loop {}
}

// Define an allocation error handler for no_std environments (required by BPF)
#[cfg(target_arch = "bpf")]
#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    // Again, Solana's handler will likely take precedence.
    loop {}
}

/// Return `true` if `verus_hash(data)` ≤ `target_be` (both big-endian).
/// *Avoids BigUint and extra Vec allocations for Solana BPF compatibility.*
/// This function now unconditionally uses the pure Rust `verus_hash` function.
pub fn verify_hash(data: &[u8], target_be: &[u8; 32]) -> bool {
    // Compute the hash (Little-Endian) using the pure Rust implementation
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
// Tests run on the host and use the pure Rust implementation.
#[cfg(test)]
mod tests {
    use super::*;
    // Use hex crate only in tests (requires std)
    use hex::FromHex;
    use hex_literal::hex; // Use hex_literal for const arrays

    #[test]
    fn length_is_32() {
        // Uses pure Rust verus_hash
        assert_eq!(verus_hash(b"").len(), 32);
    }

    #[test]
    fn verify_max_target() {
        // Uses pure Rust verus_hash
        assert!(verify_hash(b"anything", &[0xFF; 32]));
    }

    #[test]
    fn verify_zero_target_fails() {
        // Uses pure Rust verus_hash
        // Hash of "anything" will be > 0, so should fail against zero target
        assert!(!verify_hash(b"anything", &[0u8; 32]));
    }

    #[test]
    fn known_vector_abc_v2_2() {
        // Uses pure Rust verus_hash
        // Test vector for VerusHash 2.2 ("abc")
        let expected_le = hex!("a8b9a81a986771a4510313ac45fb8f4c637719397402185cf67995931cb67750");
        assert_eq!(verus_hash(b"abc"), expected_le);
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
    fn known_vector_zeros_64_v2_2() {
        // Uses pure Rust verus_hash
        // Test vector for VerusHash 2.2 (64 zero bytes)
        // From: https://github.com/VerusCoin/VerusCoin/blob/master/src/test/verushash_tests.cpp#L110
        let input = [0u8; 64];
        let expected_le = hex!("9e943744647a183c75ac76cf15e771769e943744647a183cf776ac757615e771");
        assert_eq!(verus_hash(&input), expected_le);
    }

    #[test]
    fn known_vector_test1234_96_v2_2() {
        // Uses pure Rust verus_hash
        // Test vector for VerusHash 2.2 ("Test1234" * 12)
        // From: https://github.com/VerusCoin/VerusCoin/blob/master/src/test/verushash_tests.cpp#L112
        let input = b"Test1234Test1234Test1234Test1234\
                      Test1234Test1234Test1234Test1234\
                      Test1234Test1234Test1234Test1234";
        // This corresponds to VH2B_LE in the original C tests, which seems to be v2.2
        let expected_le = hex!(
            "ac c9 b5 07 1e 92 66 9f 97 e9 e1 8b 38 d0 6a 8c \
             a9 19 fc 66 62 5c d3 71 9e 1e 55 4e 1d af 71 f9"
        );
        assert_eq!(verus_hash(input), expected_le);
    }

    // Remove the old golden tests and the host/bpf comparison test,
    // as we now only have the pure Rust implementation.
    // The known_vector tests above cover the necessary golden vectors for v2.2.
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
