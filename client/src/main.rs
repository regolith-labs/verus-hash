use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
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
    let payer_path = dirs::home_dir().unwrap().join(".config/solana/id.json");
    let payer =
        read_keypair_file(&payer_path).map_err(|_err| anyhow::anyhow!("failed to read keypair"))?;

    // 2) Define challenge and difficulty
    // TODO: These should likely come from command-line arguments or configuration
    // Using a placeholder challenge for now. In a real scenario, this might
    // come from the network state or a specific account.
    let challenge = [255u8; 32];
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

    // 4) Encode instruction data for Opcode 0 (Matches program::Args struct)
    // WARNING: Opcode 0 is currently unimplemented in the program.
    // This transaction will fail until Opcode 0 is implemented.
    // To use Opcode 1, the data encoding and instruction creation need to change.
    let mut instruction_data = Vec::with_capacity(1 + 8 + 8); // opcode + difficulty + nonce
    instruction_data.push(0u8); // Opcode 0
    instruction_data.extend_from_slice(&difficulty.to_le_bytes());
    instruction_data.extend_from_slice(&nonce_bytes); // Append found nonce bytes

    // 5) Build instruction
    let program_pubkey = Pubkey::from_str(PROGRAM_ID)?;
    let ix = Instruction {
        program_id: program_pubkey,
        // Opcode 0 expects the signer account
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: instruction_data,
    };

    // 6) Send transaction
    println!("Sending transaction...");
    let recent_blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix], // Only include our instruction for now
        Some(&payer.pubkey()),
        &[&payer],
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
    // Use the difficulty_to_target function from the verus crate
    let target_be = verus::difficulty_to_target(difficulty);
    println!("Target (BE): {:x?}", target_be);

    // Also print target in Little-Endian for easier comparison with hash output
    let mut target_le = [0u8; 32];
    for i in 0..32 {
        target_le[i] = target_be[31 - i];
    }
    println!("Target (LE): {:x?}", target_le);

    // Print components being hashed
    println!("Hashing Data Components:");
    println!("  Challenge: {:x?}", challenge);
    println!("  Signer:    {}", signer);
    // Nonce will be printed in the loop

    let mut nonce_val = 0u64;
    let start_time = Instant::now(); // For calculating hash rate

    loop {
        let nonce_bytes = nonce_val.to_le_bytes();

        // Construct hash data: challenge + signer + nonce
        // Note: The order must match what the program expects if using Opcode 0.
        // If using Opcode 1, the program expects `msg`, which would be this data.
        let mut hash_data = Vec::with_capacity(32 + 32 + 8);
        hash_data.extend_from_slice(challenge);
        hash_data.extend_from_slice(signer.as_ref());
        hash_data.extend_from_slice(&nonce_bytes);

        // Compute the hash (Little-Endian)
        let hash_le = verus::verus_hash(&hash_data);

        // Verify hash against the Big-Endian target
        // Note: verify_hash internally computes the hash again, but we need hash_le for debugging.
        // In a performance-critical scenario, we might refactor verify_hash to accept a precomputed LE hash.
        if verus::verify_hash(&hash_data, &target_be) {
            let elapsed = start_time.elapsed();
            let rate = nonce_val as f64 / elapsed.as_secs_f64();
            println!(
                "Found valid hash (LE): {:x?} <= Target (LE): {:x?}",
                &hash_le[..8], // Show first 8 bytes for brevity
                &target_le[..8]
            );
            println!("Checked {} nonces. Rate: {:.2} H/s", nonce_val + 1, rate);
            return nonce_bytes;
        }

        nonce_val += 1;

        // Print progress occasionally without slowing down too much
        // Also print current hash vs target LE comparison
        if nonce_val % 500_000 == 0 {
            // Check more frequently
            let elapsed = start_time.elapsed();
            if elapsed.as_secs() > 0 {
                let rate = nonce_val as f64 / elapsed.as_secs_f64();
                // Show first 8 bytes of LE hash vs LE target
                println!(
                    "...checked {} nonces. Rate: {:.2} H/s. Hash (LE): {:x?} vs Target (LE): {:x?}",
                    nonce_val,
                    rate,
                    &hash_le[..8],   // Show first 8 bytes
                    &target_le[..8]  // Show first 8 bytes
                );
            }
        }
        // Add a safety break for testing/debugging if needed,
        // but in a real client, this might run indefinitely.
        // if nonce_val > 10_000_000 { // Example safety break
        //     panic!("Nonce search safety break reached");
        // }
    }
}
