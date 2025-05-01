// Removed drillx::Solution as it's no longer used client-side for verification
use solana_program::hash::Hash;
use solana_program::pubkey::Pubkey; // Added for find_nonce
use solana_program_test::{processor, BanksClient, ProgramTest};
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

#[tokio::test]
async fn test_initialize() {
    // Setup
    // Removed `mut` from banks as it's not mutated
    let (banks, payer, blockhash) = setup_program_test_env().await;

    // Define challenge and difficulty for testing
    let challenge = [255u8; 32]; // Use the same placeholder challenge as program
    let base_difficulty = 20u64; // Moderate difficulty for testing PoW search
    let high_difficulty = 24u64; // Slightly higher difficulty, expected to fail quickly

    // Find a valid nonce for the base difficulty
    // Note: This now uses the actual VerusHash C implementation via the 'portable' feature.
    println!(
        "Searching for a valid nonce for difficulty {}...",
        base_difficulty
    );
    let nonce_ok = find_nonce(&challenge, &payer.pubkey(), base_difficulty);
    println!("Found nonce: {:?}", nonce_ok);
    // Create a different nonce (e.g., by incrementing) to test invalid cases.
    // Using wrapping_add ensures it handles overflow correctly if nonce_ok is u64::MAX.
    let nonce_bad = nonce_ok.map(|b| b.wrapping_add(1));

    // Test 1: Valid nonce, base difficulty -> Should succeed
    println!("Testing: Valid nonce, base difficulty (should succeed)");
    let tx1 = build_tx(&payer, base_difficulty, nonce_ok, blockhash);
    assert!(banks.process_transaction(tx1).await.is_ok());

    // Test 2: Valid nonce, high difficulty -> Should fail
    println!("Testing: Valid nonce, high difficulty (should fail)");
    let tx2 = build_tx(&payer, high_difficulty, nonce_ok, blockhash);
    assert!(banks.process_transaction(tx2).await.is_err());

    // Test 3: Invalid nonce, base difficulty -> Should fail
    println!("Testing: Invalid nonce, base difficulty (should fail)");
    let tx3 = build_tx(&payer, base_difficulty, nonce_bad, blockhash);
    assert!(banks.process_transaction(tx3).await.is_err());
}

/// Finds a nonce that satisfies the difficulty requirement using the host stub hash.
/// WARNING: Uses host-side stub (SHA256), not VerusHash. Only for logic testing.
fn find_nonce(challenge: &[u8; 32], signer: &Pubkey, difficulty: u64) -> [u8; 8] {
    let target = program::difficulty_to_target(difficulty); // Use the program's function
                                                            // Initialize nonce_val only, nonce_bytes is assigned inside the loop
    let mut nonce_val = 0u64;

    loop {
        let nonce_bytes: [u8; 8]; // Declare here, assign below
                                  // Construct hash data: challenge + signer + nonce
        let mut hash_data = Vec::with_capacity(32 + 32 + 8);
        hash_data.extend_from_slice(challenge);
        hash_data.extend_from_slice(signer.as_ref());
        nonce_bytes = nonce_val.to_le_bytes();
        hash_data.extend_from_slice(&nonce_bytes);

        // Verify using the host stub hash logic from verus crate
        // Note: verus::verify_hash uses verus::verus_hash internally, which is the stub on host.
        if verus::verify_hash(&hash_data, &target) {
            return nonce_bytes;
        }

        nonce_val += 1;
        if nonce_val % 10000 == 0 {
            // Print progress occasionally
            println!("...checked {} nonces", nonce_val);
        }
        if nonce_val > 1_000_000 {
            // Safety break for tests
            // Reduce safety break limit as portable C hash is slower than the stub
            panic!("Could not find a valid nonce within 200,000 iterations for difficulty {}. Target: {:x?}", difficulty, target);
        }
    }
}

fn build_tx(payer: &Keypair, difficulty: u64, nonce: [u8; 8], blockhash: Hash) -> Transaction {
    let cu_budget_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    // Updated call to verify: takes nonce directly
    let ix = program::verify(payer.pubkey(), difficulty, nonce);
    Transaction::new_signed_with_payer(
        &[cu_budget_ix, ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    )
}

async fn setup_program_test_env() -> (BanksClient, Keypair, Hash) {
    // Added `mut` to program_test to allow calling prefer_bpf
    let mut program_test = ProgramTest::new(
        "program",
        program::id(),
        processor!(program::process_instruction),
    );
    program_test.prefer_bpf(true);
    program_test.start().await
}
