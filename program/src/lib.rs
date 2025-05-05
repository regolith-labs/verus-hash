#![cfg_attr(not(target_os = "solana"), allow(unexpected_cfgs))] // Silence host build warnings

use bytemuck::{Pod, Zeroable};
use solana_program::{
    self,
    account_info::AccountInfo, // Removed next_account_info
    declare_id,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    log::sol_log_compute_units,
    program_error::ProgramError,
    pubkey::Pubkey,
};

declare_id!("DCCoS9rqVhJyq17XAizxntC4Hw9rHaXjZRsC53kHHMgp");

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo], // Marked unused for now
    ix_data: &[u8],
) -> ProgramResult {
    // Match on the first byte (opcode)
    match ix_data.first() {
        // Opcode 0: Placeholder for original logic (if needed later)
        // Currently, the original logic required specific accounts and Args struct.
        // Re-implementing it here would require parsing Args from ix_data[1..]
        // and accessing accounts. For now, return error.
        Some(0) => {
            // Example: If you wanted to keep the old logic for opcode 0
            /*
            if ix_data.len() - 1 != std::mem::size_of::<Args>() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let args = Args::try_from_bytes(&ix_data[1..])?;
            let accounts_iter = &mut _accounts.iter();
            let signer_info = next_account_info(accounts_iter)?;
            if !signer_info.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let challenge = [255u8; 32]; // Placeholder
            let mut hash_data = Vec::with_capacity(32 + 32 + 8);
            hash_data.extend_from_slice(&challenge);
            hash_data.extend_from_slice(signer_info.key.as_ref());
            hash_data.extend_from_slice(&args.nonce);
            let target_be = difficulty_to_target(args.difficulty);
            sol_log_compute_units();
            if !verus::verify_hash(&hash_data, &target_be) {
                return Err(ProgramError::Custom(2)); // Error 2: Hash verification failed
            }
            sol_log_compute_units();
            Ok(())
            */
            // For now, just return an error indicating opcode 0 is not implemented
            Err(ProgramError::InvalidInstructionData) // Or a custom error
        }

        // ---------------------------------------------------------------
        // NEW OPCODE 1  → server-side verify
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
                    "Error: Invalid instruction data length. Expected 100 bytes after opcode, got {}",
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
                    "Error: Invalid message length in instruction data. Expected 64, got {}",
                    msg_len
                );
                return Err(ProgramError::InvalidInstructionData);
            }

            // Advance the slice past the length field
            p = &p[4..]; // p now points to the start of the 64-byte message

            // Slice the message (64 bytes) and target (32 bytes)
            // No need to check length again, already validated p.len() == 100 above
            let msg = &p[..64]; // The 64-byte message: challenge(32) + signer[0..24](24) + nonce(8)
            let target = &p[64..96]; // The 32-byte target

            // Safely convert target slice to fixed-size array
            let target_be: &[u8; 32] = target
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?; // Should match size 32

            // --- Log the hash calculated by the program ---
            // The `msg` slice is now the correct 64-byte buffer to hash
            let hash_le = verus::verus_hash(msg); // Calculate hash (LE) of the 64-byte message
            let mut hash_be = [0u8; 32];
            for i in 0..32 {
                hash_be[i] = hash_le[31 - i]; // Convert to BE
            }
            solana_program::msg!("Program received msg (64 bytes): {:x?}", msg); // Log the message being hashed
            solana_program::msg!("Program calculated hash (LE): {:x?}", hash_le);
            solana_program::msg!("Program calculated hash (BE): {:x?}", hash_be);
            solana_program::msg!("Target (BE): {:x?}", target_be);
            // --- End logging ---

            // Perform the verification using the verus crate.
            // It will hash the provided 64-byte `msg` and compare against `target_be`.
            if verus::verify_hash(msg, target_be) {
                solana_program::msg!("Hash verification successful (program).");
                sol_log_compute_units(); // Log CUs on success
                Ok(())
            } else {
                solana_program::msg!(
                    "Hash verification failed (program calculated hash > target)."
                );
                // Use a distinct error code for failed hash verification
                Err(ProgramError::Custom(1)) // Error 1: Hash verification failed (hash > target)
            }
        }

        // Handle unknown opcodes or empty instruction data
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Converts a difficulty value into a 32-byte big-endian target.
/// target = floor(2^256 / (difficulty + 1)) approximately, or more simply
// difficulty_to_target moved to verus crate

// Updated verify helper function (removed digest) - THIS IS LIKELY BROKEN NOW
// as process_instruction expects opcode 0, which is currently unimplemented.
// Keep it for now, but it needs adjustment if opcode 0 is implemented.
pub fn verify(signer: Pubkey, difficulty: u64, nonce: [u8; 8]) -> Instruction {
    // This constructs data for the OLD format (Args struct).
    // To call the new opcode 1, a different helper is needed.
    // To call opcode 0, it needs to be implemented first.
    let args_data = Args { difficulty, nonce }.to_bytes().to_vec();
    let mut instruction_data = vec![0u8]; // Prepend opcode 0
    instruction_data.extend(args_data);

    Instruction {
        program_id: crate::id(),
        accounts: vec![AccountMeta::new(signer, true)], // Opcode 0 might need this
        data: instruction_data,
    }
}

// Updated Args struct (removed digest) - Only used by the (broken) verify helper above.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct Args {
    pub difficulty: u64,
    pub nonce: [u8; 8],
}

impl Args {
    pub fn to_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    // This function is likely unused now as process_instruction uses ix_data directly
    #[allow(dead_code)]
    fn try_from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        bytemuck::try_from_bytes::<Self>(data).or(Err(ProgramError::InvalidAccountData))
    }
}
