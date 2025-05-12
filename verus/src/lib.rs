// Define the Solution enum if it's not already defined elsewhere accessible here.
// This is a placeholder; actual values might come from a shared constants crate or similar.
#[cfg(feature = "portable")]
mod portable_verus_hash {
    // Define constants for solution versions if needed by C++ side,
    // though for Finalize() path it might not be strictly necessary for the C FFI.
    // const SOLUTION_VERUSHHASH_V2: i32 = 1; // Example

    #[link(name = "verushash", kind = "static")]
    extern "C" {
        // FFI for VerusHash V1 (if still needed/exposed)
        // fn verus_hash(output: *mut u8, input: *const u8, input_len: usize);

        // FFI for VerusHash V2 (Finalize path)
        fn verus_hash_v2_c(output: *mut u8, input: *const u8, input_len: usize);
    }

    /// Computes the VerusHash 2.0 (using Finalize method) for the given input data.
    ///
    /// # Arguments
    ///
    /// * `input`: A slice of bytes to hash.
    ///
    /// # Returns
    ///
    /// A 32-byte array representing the hash.
    pub fn verus_hash_v2(input: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe {
            verus_hash_v2_c(output.as_mut_ptr(), input.as_ptr(), input.len());
        }
        output
    }
}

#[cfg(feature = "portable")]
pub use portable_verus_hash::verus_hash_v2;

// If you have other specific implementations for non-portable (e.g., direct Rust or other FFI),
// they would go into respective cfg blocks.

// Example of how you might structure if you also had a non-portable version
// (though for this task, we are focusing on the C FFI via "portable" feature)
/*
#[cfg(not(feature = "portable"))]
mod native_verus_hash {
    // Potentially a pure Rust implementation or different FFI
    pub fn verus_hash_v2(input: &[u8]) -> [u8; 32] {
        // Placeholder for a native/different implementation
        unimplemented!("Native VerusHash V2 not implemented for this target configuration");
        // Or, if you had a pure Rust version:
        // rust_verus_hash::hash_v2(input)
    }
}

#[cfg(not(feature = "portable"))]
pub use native_verus_hash::verus_hash_v2;
*/

// Ensure that at least one implementation is available.
// The `default = ["portable"]` in Cargo.toml should handle this.
