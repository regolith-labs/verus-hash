#![cfg_attr(not(target_os = "solana"), allow(unexpected_cfgs))] // Silence host build warnings

use bytemuck::{Pod, Zeroable};
use solana_program::{
    self,
    account_info::{next_account_info, AccountInfo},
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
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Basic validation
    if data.len() != std::mem::size_of::<Args>() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let args = Args::try_from_bytes(data)?;
    let accounts_iter = &mut accounts.iter();
    let signer_info = next_account_info(accounts_iter)?;

    // Ensure signer is valid
    if !signer_info.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // TODO: Derive the actual challenge based on program state/inputs
    let challenge = [255u8; 32]; // Placeholder challenge

    // Construct the data to be hashed: challenge + signer pubkey + nonce
    let mut hash_data = Vec::with_capacity(32 + 32 + 8);
    hash_data.extend_from_slice(&challenge);
    hash_data.extend_from_slice(signer_info.key.as_ref());
    hash_data.extend_from_slice(&args.nonce);

    // Calculate the target from the provided difficulty
    let target_be = difficulty_to_target(args.difficulty);

    sol_log_compute_units(); // Log CUs before hash

    // Verify the hash against the target
    if !verus::verify_hash(&hash_data, &target_be) {
        // Use a distinct error code for failed hash verification
        return Err(ProgramError::Custom(2)); // Error 2: Hash verification failed
    }

    sol_log_compute_units(); // Log CUs after hash
    Ok(())
}

/// Converts a difficulty value into a 32-byte big-endian target.
/// target = floor(2^256 / (difficulty + 1)) approximately, or more simply
/// target = MAX_TARGET >> difficulty
/// where MAX_TARGET is 2^256 - 1 ([0xFF; 32]).
/// Made public for use in tests.
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
        for i in 0..32 {
            // Iterate from left (MSB) to right (LSB)
            let current_byte = target[i];
            // Shift the current byte right, and bring in the carry from the left byte's shift-out
            target[i] = (current_byte >> bit_shifts) | carry;
            // Calculate the new carry for the next byte (to the right)
            // These are the bits shifted out from the current byte, positioned correctly.
            carry = (current_byte << (8 - bit_shifts)) & 0xFF;
        }
    }

    // Apply byte shifts (shifting right, filling with zeros from the left)
    if byte_shifts > 0 {
        // Shift existing bytes to the right
        for i in (byte_shifts..32).rev() {
            target[i] = target[i - byte_shifts];
        }
        // Fill the newly opened space at the left (MSB) with zeros
        for i in 0..byte_shifts {
            target[i] = 0;
        }
    }

    target
}

// Updated verify helper function (removed digest)
pub fn verify(signer: Pubkey, difficulty: u64, nonce: [u8; 8]) -> Instruction {
    Instruction {
        program_id: crate::id(),
        accounts: vec![AccountMeta::new(signer, true)],
        data: Args { difficulty, nonce }.to_bytes().to_vec(),
    }
}

// Updated Args struct (removed digest)
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

    fn try_from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        bytemuck::try_from_bytes::<Self>(&data).or(Err(ProgramError::InvalidAccountData))
    }
}
