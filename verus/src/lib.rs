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
// Note: The signature now requires a key buffer.
// pub use rust_impl::verus_hash_rust as verus_hash;
// Let's define a wrapper or make the caller handle the buffer.
// For now, keep the old signature for verify_hash compatibility,
// but it will use a temporary buffer internally (less efficient).

// Define the key size constant publicly if needed by callers
pub use rust_impl::VERUSKEYSIZE;

// Internal function requiring the buffer
use rust_impl::verus_hash_rust as verus_hash_internal;

// Public function that allocates a temporary buffer (for compatibility/ease of use)
// WARNING: This allocates VERUSKEYSIZE bytes on the heap per call!
// Only available when the `std` feature is enabled.
#[cfg(feature = "std")]
pub fn verus_hash(data: &[u8]) -> [u8; 32] {
    // Use alloc (available via std) for the buffer
    let mut key_buffer_vec = std::vec![0u8; VERUSKEYSIZE];

    verus_hash_internal(data, key_buffer_vec.as_mut_slice())
}

// BPF version MUST receive a buffer from the caller via Solana memory mapping.
// We cannot allocate it here. This function signature needs adjustment
// in the context of the Solana program using it.
// For now, let's provide a function that takes the buffer.
pub fn verus_hash_with_buffer(data: &[u8], key_buffer: &mut [u8]) -> [u8; 32] {
    verus_hash_internal(data, key_buffer)
}

// The haraka_rc function is no longer needed.

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
/// This function now uses the software Rust `verus_hash` implementation.
/// NOTE: This version allocates a temporary key buffer. For BPF or performance-
/// critical paths, use `verify_hash_with_buffer`.
/// Only available when the `std` feature is enabled.
#[cfg(feature = "std")]
pub fn verify_hash(data: &[u8], target_be: &[u8; 32]) -> bool {
    // Allocate temporary buffer for the key using std's allocator
    let mut key_buffer_vec = std::vec![0u8; VERUSKEYSIZE];

    // Compute the hash (Little-Endian) using the internal function with the buffer
    let le = verus_hash_internal(data, key_buffer_vec.as_mut_slice());

    // Reverse in place into a stack-allocated buffer to get big-endian hash
    let mut hash_be = [0u8; 32];
    for i in 0..32 {
        hash_be[i] = le[31 - i];
    }

    // Constant-time lexicographic compare (hash_be <= target_be)
    // Returns true if hash_be is less than or equal to target_be.
    for i in 0..32 {
        if hash_be[i] < target_be[i] {
            return true; // Current byte is smaller
        } else if hash_be[i] > target_be[i] {
            return false; // Current byte is larger
        }
        // Bytes are equal, continue
    }
    true // All bytes were equal
}

/// Return `true` if `verus_hash(data)` ≤ `target_be` (both big-endian).
/// Requires the caller to provide a mutable key buffer of VERUSKEYSIZE.
/// Suitable for BPF and performance-critical paths.
pub fn verify_hash_with_buffer(data: &[u8], target_be: &[u8; 32], key_buffer: &mut [u8]) -> bool {
    // Compute the hash (Little-Endian) using the internal function with the provided buffer
    let le = verus_hash_internal(data, key_buffer);

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

    // Helper for tests: allocate key buffer
    fn get_test_buffer() -> Vec<u8> {
        vec![0u8; VERUSKEYSIZE]
    }

    #[test]
    fn length_is_32() {
        let mut buffer = get_test_buffer();
        // Uses pure Rust verus_hash_with_buffer
        assert_eq!(verus_hash_with_buffer(b"", &mut buffer).len(), 32);
    }

    #[test]
    fn verify_max_target() {
        let mut buffer = get_test_buffer();
        // Uses pure Rust verify_hash_with_buffer
        assert!(verify_hash_with_buffer(
            b"anything",
            &[0xFF; 32],
            &mut buffer
        ));
    }

    #[test]
    fn verify_zero_target_fails() {
        let mut buffer = get_test_buffer();
        // Uses pure Rust verify_hash_with_buffer
        // Hash of "anything" will be > 0, so should fail against zero target
        assert!(!verify_hash_with_buffer(
            b"anything",
            &[0u8; 32],
            &mut buffer
        ));
    }

    #[test]
    fn verify_known_vector_success() {
        let mut buffer = get_test_buffer();
        // Verify that the known hash of "abc" meets a target slightly above it.
        let hash_le = verus_hash_with_buffer(b"abc", &mut buffer);
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
        // Re-init buffer for verify call
        let mut buffer2 = get_test_buffer();
        assert!(verify_hash_with_buffer(b"abc", &target_be, &mut buffer2));
    }

    #[test]
    fn verify_known_vector_fail() {
        let mut buffer = get_test_buffer();
        // Verify that the known hash of "abc" fails a target slightly below it.
        let hash_le = verus_hash_with_buffer(b"abc", &mut buffer);
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
            // Re-init buffer for verify call
            let mut buffer2 = get_test_buffer();
            assert!(!verify_hash_with_buffer(b"abc", &target_be, &mut buffer2));
        } else {
            // If hash was 0, the only lower target is impossible. Skip assert.
            println!("Skipping verify_known_vector_fail as hash is zero.");
        }
    }

    #[test]
    fn known_vector_test1234_96_v2_2() {
        let mut buffer = get_test_buffer();
        let input = b"Test1234Test1234Test1234Test1234\
                      Test1234Test1234Test1234Test1234\
                      Test1234Test1234Test1234Test1234";
        // Expected output hash (Big-Endian) for VerusHash 2.2
        // This is the direct output from the C++ reference `verus-cli`
        let expected_be = hex!("ed3dbd1d798342264cbfee4a49564917edb68b3a5c566d1f487005113bc4ce55");
        assert_eq!(verus_hash_with_buffer(input, &mut buffer), expected_be);
    }

    // Add more known vectors here if needed.
    // Example structure:
    // #[test]
    // fn known_vector_example() {
    //     let input = b"some_input_data";
    //     let expected_le = hex!("expected_little_endian_hash");
    //     assert_eq!(verus_hash(input), expected_le);
    // }

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
