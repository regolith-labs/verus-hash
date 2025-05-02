use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    // instruction::{AccountMeta, Instruction}, // AccountMeta removed
    instruction::Instruction, // Keep Instruction
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use std::{str::FromStr, time::Instant}; // Added Instant for timing
use verus; // Import the verus crate

// ------------------------------------------------------------------
// CONFIG
// ------------------------------------------------------------------
const PROGRAM_ID: &str = "DCCoS9rqVhJyq17XAizxntC4Hw9rHaXjZRsC53kHHMgp";
const RPC_URL: &str = "http://localhost:8899";
// ------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    // 1) connection + payer
    let client = RpcClient::new_with_commitment(RPC_URL.to_string(), CommitmentConfig::confirmed());
    println!("RC[0..16] in client  = {:02x?}", &verus::haraka_rc()[..16]); // Print constants used by client
    let payer_path = dirs::home_dir().unwrap().join(".config/solana/id.json");
    let payer =
        read_keypair_file(&payer_path).map_err(|_err| anyhow::anyhow!("failed to read keypair"))?;

    // 2) Define challenge and difficulty
    // TODO: These should likely come from command-line arguments or configuration
    // Using a placeholder challenge for now. In a real scenario, this might
    // come from the network state or a specific account.
    let challenge = [0u8; 32]; // Use zero challenge for testing
    let difficulty: u64 = 5; // Lowered difficulty significantly for faster testing

    // 3) Find a valid nonce
    println!(
        "Searching for nonce with difficulty {} for signer {}...",
        difficulty,
        payer.pubkey()
    );
    let start_time = Instant::now();
    let nonce_bytes = find_nonce(&challenge, &payer.pubkey(), difficulty);
    let elapsed = start_time.elapsed();
    println!("Found nonce {:?} in {:.2?}", nonce_bytes, elapsed);

    // 4) Encode instruction data for Opcode 1 (On-chain verification)
    // data = opcode(1) | msg_len(4 LE) | msg(challenge(32) + signer(32) + nonce(8)) | target_BE(32)
    let target_be = verus::difficulty_to_target(difficulty); // Get Big-Endian target for the program
    println!(
        "Calculated Target (BE) for on-chain verification: {:x?}",
        target_be
    );

    // Construct the 64-byte message: challenge (32) + signer[0..24] (24) + nonce (8)
    let mut msg_data = [0u8; 64];
    msg_data[..32].copy_from_slice(&challenge); // Pass as slice reference
    msg_data[32..56].copy_from_slice(&payer.pubkey().to_bytes()[..24]); // First 24 bytes of signer
    msg_data[56..64].copy_from_slice(&nonce_bytes); // 8 bytes nonce
    let msg_len: u32 = msg_data.len() as u32; // Should be 64

    // Construct the full instruction data: opcode(1) | msg_len(4 LE = 64) | msg(64) | target(32)
    let mut instruction_data = Vec::with_capacity(1 + 4 + 64 + 32); // 1 + 4 + 64 + 32 = 101 bytes
    instruction_data.push(1u8); // Opcode 1
    instruction_data.extend_from_slice(&msg_len.to_le_bytes()); // Message length (4 bytes LE = 64)
    instruction_data.extend_from_slice(&msg_data); // The actual message (64 bytes)
    instruction_data.extend_from_slice(&target_be); // Target (Big-Endian, 32 bytes)

    // 5) Build instruction for Opcode 1 (no accounts needed)
    let program_pubkey = Pubkey::from_str(PROGRAM_ID)?;
    let ix = Instruction {
        program_id: program_pubkey,
        accounts: vec![], // Opcode 1 does not require any accounts
        data: instruction_data,
    };

    // 6) Send transaction for on-chain verification
    println!("Sending transaction for on-chain verification...");
    let recent_blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],                 // Only include our Opcode 1 instruction
        Some(&payer.pubkey()), // Payer is still the fee payer
        &[&payer],             // Signer is the fee payer
        recent_blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            println!("✅ Transaction successful! Signature: {}", sig);
        }
        Err(e) => {
            eprintln!("❌ Transaction failed: {}", e);
            // Consider adding more specific error handling if needed
            return Err(anyhow::anyhow!("Transaction failed"));
        }
    }

    Ok(())
}

/// Finds a nonce that satisfies the difficulty requirement using VerusHash.
fn find_nonce(challenge: &[u8; 32], signer: &Pubkey, difficulty: u64) -> [u8; 8] {
    // Calculate the target in big-endian based on difficulty
    let target_be = verus::difficulty_to_target(difficulty);
    println!("Target (BE): {:x?}", target_be); // Print the calculated BE target

    // Print components being hashed
    println!("Hashing Data Components:");
    println!("  Challenge: {:x?}", challenge);
    println!("  Signer:    {}", signer);
    // Nonce will be printed in the loop

    let mut nonce_val = 0u64;
    let start_time = Instant::now(); // For calculating hash rate
    let mut log_counter = 0; // Counter for logging initial hashes

    loop {
        let nonce_bytes = nonce_val.to_le_bytes();

        // Construct the 64-byte hash data: challenge (32) + signer[0..24] (24) + nonce (8)
        let mut hash_data = [0u8; 64];
        hash_data[..32].copy_from_slice(challenge); // Pass challenge directly (it's already a reference)
        hash_data[32..56].copy_from_slice(&signer.to_bytes()[..24]); // Use signer directly
        hash_data[56..64].copy_from_slice(&nonce_bytes); // 8 bytes nonce

        // Compute the hash (Little-Endian) using the 64-byte buffer
        let hash_le = verus::verus_hash(&hash_data);

        // Convert hash to Big-Endian for comparison
        let mut hash_be = [0u8; 32];
        for i in 0..32 {
            hash_be[i] = hash_le[31 - i];
        }

        // Log the first few hashes regardless of success
        if log_counter < 10 {
            // Log first 10 hashes
            println!(
                "Nonce: {:<10} | Hash (BE): {:x?}",
                nonce_val,
                hash_be // Show full BE hash
            );
            log_counter += 1;
        }

        // Verify hash against the big-endian target using standard comparison
        // hash_be <= target_be
        if hash_be <= target_be {
            let elapsed = start_time.elapsed();
            let rate = if elapsed.as_secs_f64() > 0.0 {
                nonce_val as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };
            println!(
                "Found valid hash (BE): {:x?} <= Target (BE): {:x?}",
                hash_be, // Show full BE hash
                target_be
            );
            println!("Checked {} nonces. Rate: {:.2} H/s", nonce_val + 1, rate);
            return nonce_bytes;
        }

        nonce_val += 1;

        // Print progress occasionally without slowing down too much
        // Also print current hash MSB vs target MSB comparison (using BE)
        // Reduce frequency to avoid clutter
        if nonce_val > 0 && nonce_val % 1_000_000 == 0 {
            let elapsed = start_time.elapsed();
            if elapsed.as_secs() > 0 {
                let rate = nonce_val as f64 / elapsed.as_secs_f64();
                // Show most significant byte (index 0) comparison from BE arrays
                println!(
                    "...checked {} nonces. Rate: {:.2} H/s. Hash MSB: {:02x} vs Target MSB: {:02x}",
                    nonce_val,
                    rate,
                    hash_be[0],   // Most significant byte of BE hash
                    target_be[0]  // Most significant byte of BE target
                );
            }
        }
        // Add a safety break for testing/debugging if needed,
        // but in a real client, this might run indefinitely.
        // if nonce_val > 1_000_000 { // Example safety break for quick tests
        //     panic!("Nonce search safety break reached");
        // }
    }
}
