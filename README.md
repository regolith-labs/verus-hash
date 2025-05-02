# Verus Hash Solana Implementation

This project implements the VerusHash v2.2 algorithm for use within the Solana blockchain environment. It consists of:

1.  **`verus` crate:** A Rust crate containing the core VerusHash logic, adapted to be compilable for both native host targets (using optimized intrinsics if available) and the Solana SBF (Solana Bytecode Format) target (using a portable C implementation).
2.  **`program` crate:** A Solana program (smart contract) written in Rust that exposes an instruction to verify a VerusHash solution on-chain. It uses the `verus` crate for the hashing logic.
3.  **`client` crate:** A command-line client application that interacts with the deployed Solana program. It uses the `verus` crate (native host version) to search for a valid nonce that satisfies a given difficulty target and then submits this solution to the on-chain program for verification.
4.  **`origin-impl` directory:** Contains the original C/C++ source code from the VerusCoin repository for reference.
5.  **`verus/c` directory:** Contains the C/C++ source code adapted for the Solana SBF environment (portable, no stdlib dependencies, etc.).

## Development & Testing Workflow

The current development cycle involves building the on-chain program, deploying it to a local validator (or testnet/devnet), and then running the client to test the interaction.

**Prerequisites:**

*   Rust toolchain installed (`rustup`)
*   Solana CLI tool suite installed
*   A running Solana validator (e.g., `solana-test-validator`)

**Steps:**

1.  **Build the Solana Program:**
    Compile the `program` crate into the SBF bytecode.

    ```bash
    cargo build-sbf

