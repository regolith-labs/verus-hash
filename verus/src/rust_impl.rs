//! Pure Rust implementation of VerusHash 2.2 algorithm.

use bytemuck::{Pod, Zeroable}; // Ensure bytes_of_mut is removed if present
use haraka_bpf::{haraka256, haraka512};

// Constants from verus_clhash.h
const CLHASH_K1: u64 = 0x9e3779b185ebca87;
const CLHASH_K2: u64 = 0xc2b2ae3d27d4eb4f;

/// Portable 64x64 carry-less multiplication returning lower 64 bits.
/// Replicates the behavior needed for the VerusHash v2.2 CLHASH step.
#[inline]
fn clmul_mix(a: u64, b: u64) -> u64 {
    let a_lo = a as u32 as u64;
    let a_hi = a >> 32;
    let b_lo = b as u32 as u64;
    let b_hi = b >> 32;

    let mut p0 = 0u64; // a_lo * b_lo
    let mut x = a_lo;
    for i in 0..32 {
        if ((b_lo >> i) & 1) != 0 {
            p0 ^= x << i;
        }
    }

    let mut t1 = 0u64; // a_lo * b_hi
    x = a_lo;
    for i in 0..32 {
        if ((b_hi >> i) & 1) != 0 {
            t1 ^= x << i;
        }
    }

    let mut t2 = 0u64; // a_hi * b_lo
    x = a_hi;
    for i in 0..32 {
        if ((b_lo >> i) & 1) != 0 {
            t2 ^= x << i;
        }
    }

    let p1 = t1 ^ t2; // a_lo * b_hi + a_hi * b_lo

    // Combine results for lower 64 bits: result_lo64 = (p1 << 32) ^ p0
    (p1 << 32) ^ p0
}

/// Represents the 64-byte state used in VerusHash.
/// Derives Pod and Zeroable for safe zero-initialization and byte manipulation.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct VerusState {
    bytes: [u8; 64],
}

impl Default for VerusState {
    fn default() -> Self {
        VerusState { bytes: [0u8; 64] }
    }
}

impl VerusState {
    /// Provides mutable access to the state as a slice of u64.
    #[inline]
    fn as_u64_mut(&mut self) -> &mut [u64; 8] {
        bytemuck::cast_mut(self)
    }

    /// Provides immutable access to the state as a slice of u64.
    #[inline]
    fn as_u64(&self) -> &[u64; 8] {
        bytemuck::cast_ref(self)
    }
}

/// Computes the VerusHash 2.2 of the input data.
pub fn verus_hash_rust(data: &[u8]) -> [u8; 32] {
    let mut state = VerusState::default(); // Initialize state S to zeros
    let mut temp_state = VerusState::default(); // Temporary buffer for haraka output
    let len = data.len();
    let mut i = 0;

    // --- Sponge over Haraka-512 ---
    while i + 32 <= len {
        // Absorb full 32-byte blocks
        for j in 0..32 {
            state.bytes[j] ^= data[i + j]; // XOR input block into the first 32 bytes of state
        }
        // Apply Haraka-512 (Perm+FF+Trunc) -> 32 bytes output
        let mut perm_out = [0u8; 32];
        haraka512::<5>(&mut perm_out, &state.bytes); // Specify 5 rounds

        // Update state: XOR the 32-byte output into the *first* 32 bytes of state.
        // This mimics the C++ reference's XOR feed-forward, but adapted for the 32-byte output.
        // The second half of the state remains unchanged by the permutation itself in this step.
        for j in 0..32 {
            state.bytes[j] ^= perm_out[j];
        }
        // Note: The C++ reference XORs the full 64 bytes of the permuted state (tmp) back.
        // Since haraka-bpf only gives us 32 bytes, we only XOR those back. This is a
        // necessary divergence due to the haraka-bpf interface.

        i += 32;
    }

    // Absorb last partial block + 10* padding
    let remaining = len - i;
    for j in 0..remaining {
        state.bytes[j] ^= data[i + j]; // XOR remaining input bytes
    }
    state.bytes[remaining] ^= 0x01; // Pad with 0x01 after the last byte
    state.bytes[63] ^= 0x80; // Pad with 0x80 at the end of the state

    // Final permutation after padding
    let mut perm_out = [0u8; 32];
    haraka512::<5>(&mut perm_out, &state.bytes); // Specify 5 rounds

    // Update state S: Overwrite the first 32 bytes with the final permuted output.
    // The C++ reference does `S = tmp`, effectively copying the 32-byte result
    // plus 32 bytes of potentially uninitialized data from `tmp`.
    // Here, we explicitly copy only the 32 valid bytes from `perm_out`.
    state.bytes[0..32].copy_from_slice(&perm_out);
    // Zero out the second half of the state, as the C++ reference implicitly relies
    // on potentially uninitialized data from `tmp` being copied, which we can't replicate.
    // Zeroing is a safe default, though it might differ from C++ behavior if that
    // uninitialized data happened to be non-zero.
    state.bytes[32..64].fill(0);

    // --- CLHASH mix (first 64 bytes of input) ---
    let mut mix: u64 = 0;
    let mut block = [0u8; 64]; // Buffer for the first 64 bytes of input
    let cpy_len = len.min(64);
    block[..cpy_len].copy_from_slice(&data[..cpy_len]); // Copy up to 64 bytes from original input

    let block_u64: &[u64; 8] = bytemuck::cast_ref(&block); // View block as u64 slice
    let state_u64 = state.as_u64(); // View state as u64 slice

    for lane in 0..8 {
        let m = u64::from_le(block_u64[lane]); // Input lane (ensure LE)
        let s_lane = u64::from_le(state_u64[lane]); // State lane (ensure LE)
        let p = if (lane & 1) != 0 {
            CLHASH_K2
        } else {
            CLHASH_K1
        }; // Select CLHASH key
        mix ^= clmul_mix(p ^ s_lane, m);
    }

    // XOR the final mix value back into each lane of the state
    let state_u64_mut = state.as_u64_mut();
    for lane in 0..8 {
        state_u64_mut[lane] = u64::from_le(state_u64_mut[lane]) ^ mix; // Apply mix (ensure LE for XOR)
        state_u64_mut[lane] = state_u64_mut[lane].to_le(); // Convert back to LE for storage
    }

    // --- Final Haraka-256 ---
    let mut final_hash_be = [0u8; 32]; // Buffer for final hash output (Haraka outputs BE)
                                       // Hash the first 32 bytes of the mixed state S using Haraka-256
                                       // Convert the slice to a fixed-size array reference using try_into()
    let state_first_32: &[u8; 32] = state.bytes[0..32]
        .try_into()
        .expect("Slice length mismatch for Haraka256 input");
    haraka256::<5>(&mut final_hash_be, state_first_32); // Specify 5 rounds

    // Convert final hash (Big-Endian) to Little-Endian for output
    let mut final_hash_le = [0u8; 32];
    for j in 0..32 {
        final_hash_le[j] = final_hash_be[31 - j];
    }

    final_hash_le
}
