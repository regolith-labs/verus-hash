#![cfg_attr(not(target_os = "solana"), allow(unexpected_cfgs))] // Silence host build warnings

use solana_program::{
    self,
    account_info::AccountInfo, // Keep for now, might be needed for future opcodes
    declare_id,
    entrypoint::ProgramResult,
    log::sol_log_compute_units,
    program_error::ProgramError,
    pubkey::Pubkey,
};
// Removed unused imports: bytemuck, AccountMeta, Instruction from solana_program

// Import hex_literal for defining the golden hash
use hex_literal::hex;

declare_id!("DCCoS9rqVhJyq17XAizxntC4Hw9rHaXjZRsC53kHHMgp");

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo], // Marked unused for now, but kept for potential future opcodes
    ix_data: &[u8],
) -> ProgramResult {
    // Match on the first byte (opcode)
    match ix_data.first() {
        // ---------------------------------------------------------------
        // OPCODE 0: Verify Golden Vector (no instruction data beyond opcode)
        // ---------------------------------------------------------------
        Some(0) => {
            sol_log_compute_units(); // Log CUs at start

            // Ensure no additional data is provided for opcode 0
            if ix_data.len() > 1 {
                solana_program::msg!("Error: Opcode 0 expects no additional instruction data.");
                return Err(ProgramError::InvalidInstructionData);
            }

            // Golden input: "Test1234" repeated 12 times
            let input_data = b"Test1234Test1234Test1234Test1234Test1234Test1234Test1234Test1234Test1234Test1234Test1234Test1234";

            // Expected output hash (Little-Endian Hex for VerusHash V2 Default/Explicit):
            let expected_hash_le =
                hex!("ed3dbd1d798342264cbfee4a49564917edb68b3a5c566d1f487005113bc4ce55");

            // Compute the hash using the verus_hash_v2 function
            let computed_hash_le = verus::verus_hash_v2(input_data);

            solana_program::msg!("Golden Input (on-chain): {:x?}", input_data);
            solana_program::msg!("Computed Hash LE (on-chain): {:x?}", computed_hash_le);
            solana_program::msg!("Expected Hash LE (on-chain): {:x?}", expected_hash_le);

            if computed_hash_le == expected_hash_le {
                solana_program::msg!("Golden vector verification successful!");
                sol_log_compute_units(); // Log CUs on success
                Ok(())
            } else {
                solana_program::msg!("Error: Golden vector verification failed.");
                Err(ProgramError::Custom(0)) // Custom error code 0 for golden vector mismatch
            }
        }

        // ---------------------------------------------------------------
        // OPCODE 1: Verify client-provided hash
        // payload = 4-byte little-endian msg_len ‖ msg ‖ 32-byte target BE
        // Accounts are not used for this opcode.
        // ---------------------------------------------------------------
        Some(1) => {
            sol_log_compute_units(); // Log CUs at start
            let mut p = &ix_data[1..]; // Start after the opcode byte

            // Expected data layout: msg_len(4 LE = 64) | msg(64) | target(32)
            // Total expected length after opcode: 4 + 64 + 32 = 100 bytes
            if p.len() != 100 {
                solana_program::msg!(
                    "Error: Invalid instruction data length for Opcode 1. Expected 100 bytes after opcode, got {}",
                    p.len()
                );
                return Err(ProgramError::InvalidInstructionData);
            }

            // Safely parse msg_len from the first 4 bytes
            let msg_len_bytes: [u8; 4] = p[..4]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let msg_len = u32::from_le_bytes(msg_len_bytes) as usize;

            // Validate msg_len is exactly 64
            if msg_len != 64 {
                solana_program::msg!(
                    "Error: Invalid message length in Opcode 1 data. Expected 64, got {}",
                    msg_len
                );
                return Err(ProgramError::InvalidInstructionData);
            }

            // Advance the slice past the length field
            p = &p[4..]; // p now points to the start of the 64-byte message

            // Slice the message (64 bytes) and target (32 bytes)
            let msg = &p[..64]; // The 64-byte message: challenge(32) + signer[0..24](24) + nonce(8)
            let target_slice = &p[64..96]; // The 32-byte target

            // Safely convert target slice to fixed-size array
            let target_be: &[u8; 32] = target_slice
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;

            // Calculate the hash using the verus crate
            let hash_le = verus::verus_hash_v2(msg); // Calculate hash (LE) of the 64-byte message

            // Convert hash to Big-Endian for comparison
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_le[31 - i]; // Convert LE to BE
            }

            solana_program::msg!("Opcode 1: Received msg (64 bytes): {:x?}", msg);
            solana_program::msg!("Opcode 1: Calculated hash (LE): {:x?}", hash_le);
            solana_program::msg!("Opcode 1: Calculated hash (BE): {:x?}", hash_be);
            solana_program::msg!("Opcode 1: Target (BE): {:x?}", target_be);

            // Perform the verification by comparing the big-endian hash with the big-endian target
            if hash_be <= *target_be {
                solana_program::msg!("Opcode 1: Hash verification successful.");
                sol_log_compute_units(); // Log CUs on success
                Ok(())
            } else {
                solana_program::msg!(
                    "Opcode 1: Hash verification failed (calculated hash > target)."
                );
                Err(ProgramError::Custom(1)) // Custom error code 1 for dynamic hash mismatch
            }
        }

        // Handle unknown opcodes or empty instruction data
        _ => {
            solana_program::msg!("Error: Unknown opcode or empty instruction data.");
            Err(ProgramError::InvalidInstructionData)
        }
    }
}
// Removed Args struct and verify helper function as they are no longer used.
