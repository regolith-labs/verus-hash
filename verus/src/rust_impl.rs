//! Pure Rust implementation of VerusHash 2.2 algorithm, based on the C++ reference.
//! Uses software implementations for AES and Haraka512.

use bytemuck::{cast_slice, Pod, Zeroable}; // Removed unused `cast`
use core::convert::TryInto; // Needed for slice conversions

// Constants from verus_clhash.h, used in the CLHASH mixing step.
const CLHASH_K1: u64 = 0x9e3779b185ebca87;
const CLHASH_K2: u64 = 0xc2b2ae3d27d4eb4f;

// --- VerusHash V2 Key Constants ---
// Made public for use in lib.rs
pub const VERUSKEYSIZE: usize = 8192 + (40 * 16); // 8832 bytes (8KiB + Haraka constants)
const VERUSKEYMASK: u64 = (1 << 13) - 1; // 8191 (Byte mask for 8KiB)

// --- AES S-box ---
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// --- Haraka Round Constants ---
// Stored as byte arrays directly from haraka_portable.c
const HARAKA_ROUND_CONSTANTS_U8: [[u8; 16]; 40] = [
    [
        0x9d, 0x7b, 0x81, 0x75, 0xf0, 0xfe, 0xc5, 0xb2, 0x0a, 0xc0, 0x20, 0xe6, 0x4c, 0x70, 0x84,
        0x06,
    ],
    [
        0x17, 0xf7, 0x08, 0x2f, 0xa4, 0x6b, 0x0f, 0x64, 0x6b, 0xa0, 0xf3, 0x88, 0xe1, 0xb4, 0x66,
        0x8b,
    ],
    [
        0x14, 0x91, 0x02, 0x9f, 0x60, 0x9d, 0x02, 0xcf, 0x98, 0x84, 0xf2, 0x53, 0x2d, 0xde, 0x02,
        0x34,
    ],
    [
        0x79, 0x4f, 0x5b, 0xfd, 0xaf, 0xbc, 0xf3, 0xbb, 0x08, 0x4f, 0x7b, 0x2e, 0xe6, 0xea, 0xd6,
        0x0e,
    ],
    [
        0x44, 0x70, 0x39, 0xbe, 0x1c, 0xcd, 0xee, 0x79, 0x8b, 0x44, 0x72, 0x48, 0xcb, 0xb0, 0xcf,
        0xcb,
    ],
    [
        0x7b, 0x05, 0x8a, 0x2b, 0xed, 0x35, 0x53, 0x8d, 0xb7, 0x32, 0x90, 0x6e, 0xee, 0xcd, 0xea,
        0x7e,
    ],
    [
        0x1b, 0xef, 0x4f, 0xda, 0x61, 0x27, 0x41, 0xe2, 0xd0, 0x7c, 0x2e, 0x5e, 0x43, 0x8f, 0xc2,
        0x67,
    ],
    [
        0x3b, 0x0b, 0xc7, 0x1f, 0xe2, 0xfd, 0x5f, 0x67, 0x07, 0xcc, 0xca, 0xaf, 0xb0, 0xd9, 0x24,
        0x29,
    ],
    [
        0xee, 0x65, 0xd4, 0xb9, 0xca, 0x8f, 0xdb, 0xec, 0xe9, 0x7f, 0x86, 0xe6, 0xf1, 0x63, 0x4d,
        0xab,
    ],
    [
        0x33, 0x7e, 0x03, 0xad, 0x4f, 0x40, 0x2a, 0x5b, 0x64, 0xcd, 0xb7, 0xd4, 0x84, 0xbf, 0x30,
        0x1c,
    ],
    [
        0x00, 0x98, 0xf6, 0x8d, 0x2e, 0x8b, 0x02, 0x69, 0xbf, 0x23, 0x17, 0x94, 0xb9, 0x0b, 0xcc,
        0xb2,
    ],
    [
        0x8a, 0x2d, 0x9d, 0x5c, 0xc8, 0x9e, 0xaa, 0x4a, 0x72, 0x55, 0x6f, 0xde, 0xa6, 0x78, 0x04,
        0xfa,
    ],
    [
        0xd4, 0x9f, 0x12, 0x29, 0x2e, 0x4f, 0xfa, 0x0e, 0x12, 0x2a, 0x77, 0x6b, 0x2b, 0x9f, 0xb4,
        0xdf,
    ],
    [
        0xee, 0x12, 0x6a, 0xbb, 0xae, 0x11, 0xd6, 0x32, 0x36, 0xa2, 0x49, 0xf4, 0x44, 0x03, 0xa1,
        0x1e,
    ],
    [
        0xa6, 0xec, 0xa8, 0x9c, 0xc9, 0x00, 0x96, 0x5f, 0x84, 0x00, 0x05, 0x4b, 0x88, 0x49, 0x04,
        0xaf,
    ],
    [
        0xec, 0x93, 0xe5, 0x27, 0xe3, 0xc7, 0xa2, 0x78, 0x4f, 0x9c, 0x19, 0x9d, 0xd8, 0x5e, 0x02,
        0x21,
    ],
    [
        0x73, 0x01, 0xd4, 0x82, 0xcd, 0x2e, 0x28, 0xb9, 0xb7, 0xc9, 0x59, 0xa7, 0xf8, 0xaa, 0x3a,
        0xbf,
    ],
    [
        0x6b, 0x7d, 0x30, 0x10, 0xd9, 0xef, 0xf2, 0x37, 0x17, 0xb0, 0x86, 0x61, 0x0d, 0x70, 0x60,
        0x62,
    ],
    [
        0xc6, 0x9a, 0xfc, 0xf6, 0x53, 0x91, 0xc2, 0x81, 0x43, 0x04, 0x30, 0x21, 0xc2, 0x45, 0xca,
        0x5a,
    ],
    [
        0x3a, 0x94, 0xd1, 0x36, 0xe8, 0x92, 0xaf, 0x2c, 0xbb, 0x68, 0x6b, 0x22, 0x3c, 0x97, 0x23,
        0x92,
    ],
    [
        0xb4, 0x71, 0x10, 0xe5, 0x58, 0xb9, 0xba, 0x6c, 0xeb, 0x86, 0x58, 0x22, 0x38, 0x92, 0xbf,
        0xd3,
    ],
    [
        0x8d, 0x12, 0xe1, 0x24, 0xdd, 0xfd, 0x3d, 0x93, 0x77, 0xc6, 0xf0, 0xae, 0xe5, 0x3c, 0x86,
        0xdb,
    ],
    [
        0xb1, 0x12, 0x22, 0xcb, 0xe3, 0x8d, 0xe4, 0x83, 0x9c, 0xa0, 0xeb, 0xff, 0x68, 0x62, 0x60,
        0xbb,
    ],
    [
        0x7d, 0xf7, 0x2b, 0xc7, 0x4e, 0x1a, 0xb9, 0x2d, 0x9c, 0xd1, 0xe4, 0xe2, 0xdc, 0xd3, 0x4b,
        0x73,
    ],
    [
        0x4e, 0x92, 0xb3, 0x2c, 0xc4, 0x15, 0x14, 0x4b, 0x43, 0x1b, 0x30, 0x61, 0xc3, 0x47, 0xbb,
        0x43,
    ],
    [
        0x99, 0x68, 0xeb, 0x16, 0xdd, 0x31, 0xb2, 0x03, 0xf6, 0xef, 0x07, 0xe7, 0xa8, 0x75, 0xa7,
        0xdb,
    ],
    [
        0x2c, 0x47, 0xca, 0x7e, 0x02, 0x23, 0x5e, 0x8e, 0x77, 0x59, 0x75, 0x3c, 0x4b, 0x61, 0xf3,
        0x6d,
    ],
    [
        0xf9, 0x17, 0x86, 0xb8, 0xb9, 0xe5, 0x1b, 0x6d, 0x77, 0x7d, 0xde, 0xd6, 0x17, 0x5a, 0xa7,
        0xcd,
    ],
    [
        0x5d, 0xee, 0x46, 0xa9, 0x9d, 0x06, 0x6c, 0x9d, 0xaa, 0xe9, 0xa8, 0x6b, 0xf0, 0x43, 0x6b,
        0xec,
    ],
    [
        0xc1, 0x27, 0xf3, 0x3b, 0x59, 0x11, 0x53, 0xa2, 0x2b, 0x33, 0x57, 0xf9, 0x50, 0x69, 0x1e,
        0xcb,
    ],
    [
        0xd9, 0xd0, 0x0e, 0x60, 0x53, 0x03, 0xed, 0xe4, 0x9c, 0x61, 0xda, 0x00, 0x75, 0x0c, 0xee,
        0x2c,
    ],
    [
        0x50, 0xa3, 0xa4, 0x63, 0xbc, 0xba, 0xbb, 0x80, 0xab, 0x0c, 0xe9, 0x96, 0xa1, 0xa5, 0xb1,
        0xf0,
    ],
    [
        0x39, 0xca, 0x8d, 0x93, 0x30, 0xde, 0x0d, 0xab, 0x88, 0x29, 0x96, 0x5e, 0x02, 0xb1, 0x3d,
        0xae,
    ],
    [
        0x42, 0xb4, 0x75, 0x2e, 0xa8, 0xf3, 0x14, 0x88, 0x0b, 0xa4, 0x54, 0xd5, 0x38, 0x8f, 0xbb,
        0x17,
    ],
    [
        0xf6, 0x16, 0x0a, 0x36, 0x79, 0xb7, 0xb6, 0xae, 0xd7, 0x7f, 0x42, 0x5f, 0x5b, 0x8a, 0xbb,
        0x34,
    ],
    [
        0xde, 0xaf, 0xba, 0xff, 0x18, 0x59, 0xce, 0x43, 0x38, 0x54, 0xe5, 0xcb, 0x41, 0x52, 0xf6,
        0x26,
    ],
    [
        0x78, 0xc9, 0x9e, 0x83, 0xf7, 0x9c, 0xca, 0xa2, 0x6a, 0x02, 0xf3, 0xb9, 0x54, 0x9a, 0xe9,
        0x4c,
    ],
    [
        0x35, 0x12, 0x90, 0x22, 0x28, 0x6e, 0xc0, 0x40, 0xbe, 0xf7, 0xdf, 0x1b, 0x1a, 0xa5, 0x51,
        0xae,
    ],
    [
        0xcf, 0x59, 0xa6, 0x48, 0x0f, 0xbc, 0x73, 0xc1, 0x2b, 0xd2, 0x7e, 0xba, 0x3c, 0x61, 0xc1,
        0xa0,
    ],
    [
        0xa1, 0x9d, 0xc5, 0xe9, 0xfd, 0xbd, 0xd6, 0x4a, 0x88, 0x82, 0x28, 0x02, 0x03, 0xcc, 0x6a,
        0x75,
    ],
];

/// Portable 64x64 carry-less multiplication returning lower 64 bits.
/// Replicates the behavior needed for the VerusHash v2.2 CLHASH step.
/// Based on the C++ reference implementation's logic.
#[inline]
fn clmul_portable(a: u64, b: u64) -> u64 {
    let a_lo = a as u32 as u64;
    let a_hi = a >> 32;
    let b_lo = b as u32 as u64;
    let b_hi = b >> 32;

    // Calculate p0 = a_lo * b_lo (carry-less)
    let mut p0 = 0u64;
    let mut x = a_lo;
    for i in 0..32 {
        if ((b_lo >> i) & 1) != 0 {
            p0 ^= x << i;
        }
    }

    // Calculate t1 = a_lo * b_hi (carry-less)
    let mut t1 = 0u64;
    x = a_lo;
    for i in 0..32 {
        if ((b_hi >> i) & 1) != 0 {
            t1 ^= x << i;
        }
    }

    // Calculate t2 = a_hi * b_lo (carry-less)
    let mut t2 = 0u64;
    x = a_hi;
    for i in 0..32 {
        if ((b_lo >> i) & 1) != 0 {
            t2 ^= x << i;
        }
    }

    // Calculate p1 = a_lo * b_hi + a_hi * b_lo (carry-less)
    let p1 = t1 ^ t2;

    // Combine results for lower 64 bits: result_lo64 = (p1 << 32) ^ p0
    (p1 << 32) ^ p0
}

// --- Software AES Implementation ---

// Galois Field (2^8) multiplication
#[inline(always)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    while a != 0 && b != 0 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    p
}

#[inline(always)]
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

#[inline(always)]
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1 (no shift)
    // Row 2 (shift left by 1)
    let tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;
    // Row 3 (shift left by 2)
    let tmp1 = state[2];
    let tmp2 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = tmp1;
    state[14] = tmp2;
    // Row 4 (shift left by 3)
    let tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

#[inline(always)]
fn mix_columns(state: &mut [u8; 16]) {
    let mut tmp = [0u8; 16];
    for c in 0..4 {
        let col_start = c * 4;
        let s0 = state[col_start];
        let s1 = state[col_start + 1];
        let s2 = state[col_start + 2];
        let s3 = state[col_start + 3];

        tmp[col_start] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        tmp[col_start + 1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        tmp[col_start + 2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        tmp[col_start + 3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
    state.copy_from_slice(&tmp);
}

#[inline(always)]
fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

// Simulates AES round (SubBytes, ShiftRows, MixColumns, AddRoundKey)
// Based on the portable C implementation's use of aesenc
#[inline(always)]
fn aes_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round_key);
}

// --- Software Haraka Permutation Helpers ---

// Simulates the MIX2 permutation using byte manipulation
#[inline(always)]
fn mix2_portable(s: &mut [[u8; 16]; 2]) {
    let mut tmp = [0u8; 16];
    let s0_orig = s[0];
    let s1_orig = s[1];

    // tmp = _mm_unpacklo_epi32(s0, s1);
    for i in 0..4 {
        tmp[i] = s0_orig[i];
    }
    for i in 0..4 {
        tmp[i + 4] = s1_orig[i];
    }
    for i in 0..4 {
        tmp[i + 8] = s0_orig[i + 4];
    }
    for i in 0..4 {
        tmp[i + 12] = s1_orig[i + 4];
    }

    // s1 = _mm_unpackhi_epi32(s0, s1);
    for i in 0..4 {
        s[1][i] = s0_orig[i + 8];
    }
    for i in 0..4 {
        s[1][i + 4] = s1_orig[i + 8];
    }
    for i in 0..4 {
        s[1][i + 8] = s0_orig[i + 12];
    }
    for i in 0..4 {
        s[1][i + 12] = s1_orig[i + 12];
    }

    // s0 = tmp;
    s[0] = tmp;
}

// Simulates the MIX4 permutation using byte manipulation
#[inline(always)]
fn mix4_portable(s: &mut [[u8; 16]; 4]) {
    let mut tmp = [0u8; 16];

    // Block 1: tmp=unpacklo(s0,s1), s0=unpackhi(s0,s1)
    let s0_orig = s[0];
    let s1_orig = s[1];
    for i in 0..4 {
        tmp[i] = s0_orig[i];
    }
    for i in 0..4 {
        tmp[i + 4] = s1_orig[i];
    }
    for i in 0..4 {
        tmp[i + 8] = s0_orig[i + 4];
    }
    for i in 0..4 {
        tmp[i + 12] = s1_orig[i + 4];
    }
    for i in 0..4 {
        s[0][i] = s0_orig[i + 8];
    }
    for i in 0..4 {
        s[0][i + 4] = s1_orig[i + 8];
    }
    for i in 0..4 {
        s[0][i + 8] = s0_orig[i + 12];
    }
    for i in 0..4 {
        s[0][i + 12] = s1_orig[i + 12];
    }

    // Block 2: s1=unpacklo(s2,s3), s2=unpackhi(s2,s3)
    let s2_orig = s[2];
    let s3_orig = s[3];
    for i in 0..4 {
        s[1][i] = s2_orig[i];
    }
    for i in 0..4 {
        s[1][i + 4] = s3_orig[i];
    }
    for i in 0..4 {
        s[1][i + 8] = s2_orig[i + 4];
    }
    for i in 0..4 {
        s[1][i + 12] = s3_orig[i + 4];
    }
    for i in 0..4 {
        s[2][i] = s2_orig[i + 8];
    }
    for i in 0..4 {
        s[2][i + 4] = s3_orig[i + 8];
    }
    for i in 0..4 {
        s[2][i + 8] = s2_orig[i + 12];
    }
    for i in 0..4 {
        s[2][i + 12] = s3_orig[i + 12];
    }

    // Block 3: s3=unpacklo(s0,s2), s0=unpackhi(s0,s2)
    let s0_orig_new = s[0]; // s0 was modified above
    let s2_orig_new = s[2]; // s2 was modified above
    for i in 0..4 {
        s[3][i] = s0_orig_new[i];
    }
    for i in 0..4 {
        s[3][i + 4] = s2_orig_new[i];
    }
    for i in 0..4 {
        s[3][i + 8] = s0_orig_new[i + 4];
    }
    for i in 0..4 {
        s[3][i + 12] = s2_orig_new[i + 4];
    }
    for i in 0..4 {
        s[0][i] = s0_orig_new[i + 8];
    }
    for i in 0..4 {
        s[0][i + 4] = s2_orig_new[i + 8];
    }
    for i in 0..4 {
        s[0][i + 8] = s0_orig_new[i + 12];
    }
    for i in 0..4 {
        s[0][i + 12] = s2_orig_new[i + 12];
    }

    // Block 4: s2=unpackhi(s1,tmp), s1=unpacklo(s1,tmp)
    let s1_orig_new = s[1]; // s1 was modified above
    let tmp_orig = tmp; // tmp holds original unpacklo(s0, s1)
    for i in 0..4 {
        s[2][i] = s1_orig_new[i + 8];
    }
    for i in 0..4 {
        s[2][i + 4] = tmp_orig[i + 8];
    }
    for i in 0..4 {
        s[2][i + 8] = s1_orig_new[i + 12];
    }
    for i in 0..4 {
        s[2][i + 12] = tmp_orig[i + 12];
    }
    for i in 0..4 {
        s[1][i] = s1_orig_new[i];
    }
    for i in 0..4 {
        s[1][i + 4] = tmp_orig[i];
    }
    for i in 0..4 {
        s[1][i + 8] = s1_orig_new[i + 4];
    }
    for i in 0..4 {
        s[1][i + 12] = tmp_orig[i + 4];
    }
}

// --- Software Haraka256 Keyed ---
// Takes 32 byte input, 20 * 16 byte round constants. Outputs 32 bytes.
fn haraka256_keyed_rust(input: &[u8; 32], round_constants: &[[u8; 16]; 20]) -> [u8; 32] {
    let mut state: [[u8; 16]; 2] = [
        input[0..16].try_into().unwrap(),
        input[16..32].try_into().unwrap(),
    ];

    // 5 Rounds
    for r in 0..5 {
        // AES Rounds (2 per Haraka round)
        aes_round(&mut state[0], &round_constants[r * 4 + 0]);
        aes_round(&mut state[1], &round_constants[r * 4 + 1]);
        aes_round(&mut state[0], &round_constants[r * 4 + 2]);
        aes_round(&mut state[1], &round_constants[r * 4 + 3]);

        // Mixing
        mix2_portable(&mut state);
    }

    // Feed-forward XOR
    for i in 0..16 {
        state[0][i] ^= input[i];
    }
    for i in 0..16 {
        state[1][i] ^= input[i + 16];
    }

    // Combine result
    let mut output = [0u8; 32];
    output[0..16].copy_from_slice(&state[0]);
    output[16..32].copy_from_slice(&state[1]);
    output
}

// --- Software Haraka512 Permutation (Unkeyed) ---
// Takes 64 byte input, uses global round constants. Outputs 64 bytes.
// Based on haraka512_perm from haraka_portable.c
fn haraka512_perm_rust(input: &[u8; 64]) -> [u8; 64] {
    // Load input into state (4x16 bytes)
    let mut state: [[u8; 16]; 4] = [
        input[0..16].try_into().unwrap(),
        input[16..32].try_into().unwrap(),
        input[32..48].try_into().unwrap(),
        input[48..64].try_into().unwrap(),
    ];

    // Use the full 40 global constants
    let constants_512: &[[u8; 16]; 40] = &HARAKA_ROUND_CONSTANTS_U8;

    // 5 Rounds
    for r in 0..5 {
        // AES Rounds (2 per Haraka round, using 8 constants each round)
        // Sub-round 0 uses constants at indices 8*r + 0..3
        aes_round(&mut state[0], &constants_512[r * 8 + 0]);
        aes_round(&mut state[1], &constants_512[r * 8 + 1]);
        aes_round(&mut state[2], &constants_512[r * 8 + 2]);
        aes_round(&mut state[3], &constants_512[r * 8 + 3]);

        // Sub-round 1 uses constants at indices 8*r + 4..7
        aes_round(&mut state[0], &constants_512[r * 8 + 4]);
        aes_round(&mut state[1], &constants_512[r * 8 + 5]);
        aes_round(&mut state[2], &constants_512[r * 8 + 6]);
        aes_round(&mut state[3], &constants_512[r * 8 + 7]);

        // Mixing
        mix4_portable(&mut state);
    }

    // Combine result (full 64 bytes)
    let mut output = [0u8; 64];
    output[0..16].copy_from_slice(&state[0]);
    output[16..32].copy_from_slice(&state[1]);
    output[32..48].copy_from_slice(&state[2]);
    output[48..64].copy_from_slice(&state[3]);
    output
}

// --- Software Haraka512 (Unkeyed, Truncated Output) ---
// Takes 64 byte input, uses global round constants. Outputs 32 bytes BE.
// Based on haraka512_port from haraka_portable.c
fn haraka512_rust(input: &[u8; 64]) -> [u8; 32] {
    // Apply the permutation
    let perm_output = haraka512_perm_rust(input);

    // Feed-forward XOR
    let mut buf = [0u8; 64];
    for i in 0..64 {
        buf[i] = perm_output[i] ^ input[i];
    }

    // Truncation (matches TRUNCSTORE macro in haraka.h) -> Big Endian result
    let mut output = [0u8; 32];
    output[0..8].copy_from_slice(&buf[8..16]); // High 64 bits of s0
    output[8..16].copy_from_slice(&buf[24..32]); // High 64 bits of s1
    output[16..24].copy_from_slice(&buf[32..40]); // Low 64 bits of s2
    output[24..32].copy_from_slice(&buf[48..56]); // Low 64 bits of s3

    output
}

// --- Software Haraka512 Keyed ---
// Takes 64 byte input, 10 * 16 byte round constants slice. Outputs 32 bytes BE.
// Note: The round_constants slice must contain exactly 10 constants for the 5 rounds.
// Note: The C++ code uses 40 constants for the keyed version too, selected by offset.
// This function needs adjustment or replacement if it's meant to match haraka512_keyed.
// Let's redefine it to match haraka512_port_keyed logic.
fn haraka512_keyed_rust(input: &[u8; 64], round_constants: &[[u8; 16]; 40]) -> [u8; 32] {
    // Load input into state (4x16 bytes)
    let mut state: [[u8; 16]; 4] = [
        input[0..16].try_into().unwrap(),
        input[16..32].try_into().unwrap(),
        input[32..48].try_into().unwrap(),
        input[48..64].try_into().unwrap(),
    ];

    // 5 Rounds using the provided (potentially offset) constants
    for r in 0..5 {
        // AES Rounds (2 per Haraka round, using 8 constants each round)
        // Sub-round 0 uses constants at indices 8*r + 0..3
        aes_round(&mut state[0], &round_constants[r * 8 + 0]);
        aes_round(&mut state[1], &round_constants[r * 8 + 1]);
        aes_round(&mut state[2], &round_constants[r * 8 + 2]);
        aes_round(&mut state[3], &round_constants[r * 8 + 3]);

        // Sub-round 1 uses constants at indices 8*r + 4..7
        aes_round(&mut state[0], &round_constants[r * 8 + 4]);
        aes_round(&mut state[1], &round_constants[r * 8 + 5]);
        aes_round(&mut state[2], &round_constants[r * 8 + 6]);
        aes_round(&mut state[3], &round_constants[r * 8 + 7]);

        // Mixing
        mix4_portable(&mut state);
    }

    // Feed-forward XOR
    let mut buf = [0u8; 64]; // Use intermediate buffer for XOR result
    buf[0..16].copy_from_slice(&state[0]);
    buf[16..32].copy_from_slice(&state[1]);
    buf[32..48].copy_from_slice(&state[2]);
    buf[48..64].copy_from_slice(&state[3]);

    for i in 0..64 {
        buf[i] ^= input[i];
    }

    // Truncation (matches TRUNCSTORE macro in haraka.h) -> Big Endian result
    let mut output = [0u8; 32];
    output[0..8].copy_from_slice(&buf[8..16]); // High 64 bits of s0
    output[8..16].copy_from_slice(&buf[24..32]); // High 64 bits of s1
    output[16..24].copy_from_slice(&buf[32..40]); // Low 64 bits of s2
    output[24..32].copy_from_slice(&buf[48..56]); // Low 64 bits of s3

    output
}

// --- Key Generation ---
// Generates the full VerusHash key into the provided buffer using Haraka256 chaining.
// Corresponds to GenNewCLKey in C++ code.
fn gen_new_cl_key_rust(seed_bytes: &[u8; 32], key_buffer: &mut [u8]) {
    assert!(
        key_buffer.len() >= VERUSKEYSIZE,
        "Key buffer too small for Verus key generation"
    );

    let num_256_blocks = VERUSKEYSIZE / 32;
    let extra_bytes = VERUSKEYSIZE % 32;

    let mut current_hash = *seed_bytes;
    let mut pkey_offset = 0;

    // Use the first 20 global constants for Haraka256
    let constants_256: &[[u8; 16]; 20] = &HARAKA_ROUND_CONSTANTS_U8[0..20].try_into().unwrap();

    for _ in 0..num_256_blocks {
        let output_hash = haraka256_keyed_rust(&current_hash, constants_256);
        key_buffer[pkey_offset..pkey_offset + 32].copy_from_slice(&output_hash);
        current_hash = output_hash;
        pkey_offset += 32;
    }

    if extra_bytes > 0 {
        let final_block_hash = haraka256_keyed_rust(&current_hash, constants_256);
        key_buffer[pkey_offset..pkey_offset + extra_bytes]
            .copy_from_slice(&final_block_hash[0..extra_bytes]);
    }
    // Note: The C++ code also copies a portion for refresh optimization, which we omit here.
    // The caller managing the buffer would need to handle refresh copies if needed.
}

// Removed get_final_keyed_constants as its logic is now inline within verus_hash_rust

/// Represents the 64-byte state used in VerusHash.
/// Derives Pod and Zeroable for safe zero-initialization and byte manipulation.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct VerusState {
    bytes: [u8; 64],
}

impl Default for VerusState {
    fn default() -> Self {
        // Safe zero-initialization thanks to Pod and Zeroable
        VerusState::zeroed()
    }
}

impl VerusState {
    /// Provides immutable access to the state as a slice of u64 (Little Endian).
    #[inline]
    fn as_u64_le(&self) -> [u64; 8] {
        // Use bytemuck to safely cast bytes to u64 array
        let u64_array: &[u64; 8] = bytemuck::cast_ref(self);
        // Ensure Little Endian interpretation if needed (bytemuck usually handles this based on target)
        // For clarity, we can explicitly convert each u64 if architecture variance is a concern,
        // but bytemuck on common LE platforms (like x86_64) should be correct.
        // Let's assume bytemuck does the right thing for the target.
        *u64_array
    }
}

/// Computes the VerusHash 2.2 of the input data using the provided key buffer.
/// Follows the logic from CVerusHashV2::Finalize2b in the C++ reference.
pub fn verus_hash_rust(data: &[u8], key_buffer: &mut [u8]) -> [u8; 32] {
    assert!(
        key_buffer.len() >= VERUSKEYSIZE,
        "Key buffer too small for VerusHash"
    );

    // State buffer (64 bytes). First 32 bytes hold the previous Haraka output (or zeros initially).
    // Second 32 bytes are XORed with the input block.
    let mut state = VerusState::default(); // Initial state is zeroed
    let len = data.len();
    let mut i = 0;

    // --- Sponge Phase ---
    // Process full 32-byte input blocks
    while i + 32 <= len {
        // XOR input block into the second half of the state
        for j in 0..32 {
            state.bytes[32 + j] ^= data[i + j];
        }

        // Apply unkeyed Haraka-512 (software version)
        // Takes 64 bytes input, produces 32 bytes output (BE).
        let haraka_out_be = haraka512_rust(&state.bytes);

        // Overwrite the first half of the state with the Haraka output.
        state.bytes[0..32].copy_from_slice(&haraka_out_be);

        // Clear the second half (where the input was XORed) for the next round.
        state.bytes[32..64].fill(0);

        i += 32;
    }

    // Process the final partial block (if any)
    let remaining = len - i;
    if remaining > 0 {
        // XOR the remaining input bytes into the second half
        for j in 0..remaining {
            state.bytes[32 + j] ^= data[i + j];
        }
        // Zero-pad the rest of the second half
        for j in remaining..32 {
            state.bytes[32 + j] = 0; // Ensure padding is zero
        }

        // Apply final unkeyed Haraka-512 for the sponge phase
        let haraka_out_be = haraka512_rust(&state.bytes);

        // Overwrite the first half of the state with the final Haraka output.
        state.bytes[0..32].copy_from_slice(&haraka_out_be);
        // Clear the second half.
        state.bytes[32..64].fill(0);
    }
    // If len was a multiple of 32, 'state' already holds the correct post-sponge state
    // (Haraka output in first 32 bytes, zeros in second 32 bytes).

    // --- CLHASH Mix Phase ---
    // Calculate the 64-bit intermediate value 'mix' based on the post-sponge state
    // and the first 64 bytes of the original input data.
    let mut mix: u64 = 0;
    let mut clhash_input_block = [0u8; 64]; // Buffer for the first 64 bytes of input
    let cpy_len = len.min(64);
    clhash_input_block[..cpy_len].copy_from_slice(&data[..cpy_len]); // Copy up to 64 bytes

    // Get state lanes as LE u64.
    let state_u64_le = state.as_u64_le(); // Reads state bytes as LE u64s

    // Get input lanes as LE u64.
    // Use bytemuck::cast for safe casting
    let clhash_input_u64_le: [u64; 8] = bytemuck::cast(clhash_input_block);

    for lane in 0..8 {
        // Ensure values are treated as Little Endian for calculation
        let m = u64::from_le(clhash_input_u64_le[lane]); // Input lane (from original data, LE)
        let s_lane = u64::from_le(state_u64_le[lane]); // State lane (post-sponge, LE)
        let p = if (lane & 1) != 0 {
            CLHASH_K2
        } else {
            CLHASH_K1
        }; // Select CLHASH key
        mix ^= clmul_portable(p ^ s_lane, m);
    }
    // 'mix' now holds the 64-bit intermediate value, calculated using LE inputs.

    // --- Final State Preparation ---
    // The first half of 'state' contains the Big Endian post-sponge Haraka result.
    // Prepare the buffer for the *keyed* Haraka by placing the
    // LE 'mix' value into the second half.
    state.bytes[32..40].copy_from_slice(&mix.to_le_bytes());
    // Zero out the remaining bytes in the second half.
    state.bytes[40..64].fill(0);

    // --- Key Generation ---
    // Generate the VerusHash key into the provided buffer using the post-sponge state as seed.
    // The seed (state.bytes[0..32]) is expected to be Big Endian from haraka512_rust.
    // gen_new_cl_key_rust expects a [u8; 32] seed.
    let seed_bytes: [u8; 32] = state.bytes[0..32]
        .try_into()
        .expect("Sponge output slice has wrong size");
    gen_new_cl_key_rust(&seed_bytes, key_buffer);

    // --- Final Haraka-512 (Keyed) ---
    // Get the specific round constants based on the 'mix' value and the generated key.
    // The C++ uses haraka512KeyedFunction which takes the full key buffer and calculates offset internally.
    // Our get_final_keyed_constants simulates this offset calculation.
    // However, haraka512_keyed_rust expects the *full* 40 constants.
    // We need to adjust get_final_keyed_constants or haraka512_keyed_rust.
    // Let's adjust get_final_keyed_constants to return the correct slice view into the main key buffer.

    // Calculate the starting byte offset for the 40 round constants needed for haraka512_keyed_rust
    // The C++ haraka512_keyed uses an offset based on 'intermediate' (our 'mix')
    // to select *which* 40 constants out of the larger key buffer to use.
    // Offset calculation: intermediate & (keyMask >> 4)
    // keyMask is byte mask (8191), >> 4 converts to u128 mask (511).
    let offset128 = (mix & (VERUSKEYMASK >> 4)) as usize;
    let start_byte = offset128 * 16; // Each constant is 16 bytes
    let constants_slice_len = 40 * 16; // Need 40 constants for 5 rounds (8 per round)
    let end_byte = start_byte + constants_slice_len;

    // Ensure the slice read is within the bounds of the main key portion (VERUSKEYSIZE bytes)
    assert!(
        end_byte <= VERUSKEYSIZE,
        "Key buffer offset calculation out of bounds for keyed Haraka constants"
    );

    // Get a slice representing the 40 round constants from the key buffer
    let final_constants_slice: &[[u8; 16]] = cast_slice(&key_buffer[start_byte..end_byte]);

    // Try to convert the slice into a reference to an array of 40 constants
    let final_constants: &[[u8; 16]; 40] = final_constants_slice
        .try_into()
        .expect("Slice length mismatch for final round constants");

    // Apply the keyed Haraka-512 using the prepared state and selected constants.
    let final_hash_be = haraka512_keyed_rust(&state.bytes, final_constants); // Output is BE

    // The final hash from haraka512_keyed_rust is Big-Endian.
    // This is the expected output format for VerusHash 2.2.
    final_hash_be
}
