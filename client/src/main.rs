use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use std::str::FromStr;

// Potentially move these to config or command-line args
const PROGRAM_ID: &str = "mineRHF5r6S7HyD9SppBfVMXMavDkJsxwGesEvxZr2A";
const RPC_URL: &str = "http://localhost:8899";

fn main() -> anyhow::Result<()> {
    // 1) connection + payer
    let client = RpcClient::new_with_commitment(
        RPC_URL.to_string(),
        solana_client::rpc_config::CommitmentConfig::confirmed(),
    );
    let payer = read_keypair_file(
        dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
            .join(".config/solana/id.json"),
    )
    .map_err(|e| anyhow::anyhow!("Failed to read keypair file: {}", e))?;

    // 2) difficulty & nonce (Example values, replace with actual logic)
    let difficulty: u64 = 0;
    let nonce_bytes: [u8; 8] = 0u64.to_le_bytes();

    // 3) encode data (little-endian) - Matches program::Args struct
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&difficulty.to_le_bytes());
    data.extend_from_slice(&nonce_bytes);

    // 4) build instruction
    let program_pubkey = Pubkey::from_str(PROGRAM_ID)?;
    let ix = Instruction {
        program_id: program_pubkey,
        accounts: vec![AccountMeta::new(payer.pubkey(), true)], // Signer is the payer
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
    println!("✅ Transaction successful, signature: {}", sig);
    Ok(())
}
