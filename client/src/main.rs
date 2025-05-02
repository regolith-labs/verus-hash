use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use std::str::FromStr;

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

    // 2) difficulty & nonce
    // TODO: These should likely come from command-line arguments or configuration
    let difficulty: u64 = 0;
    let nonce_bytes: [u8; 8] = 0u64.to_le_bytes(); // Use [u8; 8] for nonce

    // 3) encode data (little-endian) - Matches program::Args struct
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&difficulty.to_le_bytes());
    data.extend_from_slice(&nonce_bytes); // Append nonce bytes

    // 4) build instruction
    let program_pubkey = Pubkey::from_str(PROGRAM_ID)?;
    let ix = Instruction {
        program_id: program_pubkey,
        // The program expects the signer account
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data,
    };

    // 5) send tx
    let recent_blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("✅  tx signature: {}", sig);
    Ok(())
}
