// program/tests/smoke.rs
use program::verify; // Use `program::` to access items from lib.rs, removed unused Args
use solana_program_test::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
};

#[tokio::test]
async fn verus_smoke_test() {
    // 1) launch local validator with your program pre-deployed
    let program_id = program::id(); // Use `program::`
                                    // Removed `mut` from test as it's only used to call start()
    let test = ProgramTest::new(
        "program", // Use the crate name defined in Cargo.toml
        program_id,
        processor!(program::process_instruction), // Use `program::`
    );
    // Removed `mut` from banks_client as it's not mutated after start()
    let (banks_client, payer, recent_blockhash) = test.start().await;

    // 2) choose a signer (payer is fine) + dummy nonce
    let signer = Keypair::new();
    let nonce = [0u8; 8];

    // 3) build the instruction exactly like a client would
    let ix = verify(signer.pubkey(), 0, nonce);

    // 4) pack in a tx and send
    let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &signer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    // 5) read the log messages back and show the CU deltas
    // Note: Getting logs directly isn't straightforward with banks_client.
    // The CU consumption is usually checked via simulation or by observing
    // the logs printed by the test validator when run with --nocapture.
    // We'll rely on the test passing and the --nocapture output for now.
    println!("Smoke test transaction successful!");
    // The CU logs will be printed to stderr by the test runner itself
    // when using `cargo test-sbf -- --nocapture`.
}
