use std::env;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let is_sbf = target.contains("sbf") || target.contains("bpf");

    // Determine if we need to build the C code.
    // We build if:
    // 1. Targeting SBF/BPF.
    // 2. The "portable" feature is enabled (which is the default for non-SBF builds).
    let build_c_code = is_sbf || env::var("CARGO_FEATURE_PORTABLE").is_ok();

    if build_c_code {
        println!("cargo:rerun-if-changed=c/verus_hash.cpp");
        println!("cargo:rerun-if-changed=c/verus_hash.h");
        println!("cargo:rerun-if-changed=c/haraka_portable.c");
        println!("cargo:rerun-if-changed=c/haraka_portable.h");
        println!("cargo:rerun-if-changed=c/uint256.cpp");
        println!("cargo:rerun-if-changed=c/uint256.h");
        println!("cargo:rerun-if-changed=c/common.h");
        // Note: verus_clhash.h is included by verus_hash.h but doesn't have a .cpp,
        // so changes there will trigger a rebuild via verus_hash.h changing.

        cc::Build::new()
            .cpp(true) // Enable C++ compilation
            .flag_if_supported("-std=c++11") // Use C++11 (required by original code)
            // Add flags to disable exceptions and RTTI for SBF compatibility
            .flag_if_supported("-fno-exceptions")
            .flag_if_supported("-fno-rtti")
            .flag_if_supported("-nostdlib++") // Don't link standard C++ library for SBF
            // Ensure our static memcpy/memset are used
            .flag_if_supported("-fno-builtin-memcpy")
            .flag_if_supported("-fno-builtin-memset")
            .include("c") // Include directory for headers
            .files([
                "c/verus_hash.cpp",
                "c/uint256.cpp",
                "c/haraka_portable.c",
            ])
            .warnings(false) // Suppress warnings from C code if necessary
            .compile("verushash"); // Output static library named libverushash.a

        // Link the compiled static library
        println!("cargo:rustc-link-lib=static=verushash");

        // For SBF, link necessary compiler builtins (like memcpy, memset if not provided)
        // Note: The static implementations in haraka_portable.c should cover these,
        // but explicitly linking compiler_builtins might be needed in some edge cases or future Rust versions.
        // if is_sbf {
        //     println!("cargo:rustc-link-lib=static=compiler_builtins");
        // }

    } else {
        // If not building C code, print a warning (e.g., host build without 'portable' feature)
        println!("cargo:warning=verus crate: Portable C backend is disabled for target '{}'. Relying on pre-compiled library or alternative implementation.", target);
        // In a real-world scenario for host, you might link a precompiled library here
        // or rely on a pure Rust implementation if available.
    }
}
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Get the target architecture from the environment variable set by Cargo
    let target = env::var("TARGET").unwrap();

    // --- Skip C/C++ build if target is not SBF ---
    // The host build (e.g., for tests or native tools) doesn't need libverushash.a
    if !target.contains("sbf") && !target.contains("bpf") {
        println!(
            "cargo:info=Skipping verus C/C++ build for non-SBF target: {}",
            target
        );
        // Still need to rerun if build script changes, even on host
        println!("cargo:rerun-if-changed=build.sh");
        return; // Exit early, do not proceed with C build or linking
    }
    println!(
        "cargo:info=Detected SBF target ({}), proceeding with verus C/C++ build...",
        target
    );
    // --- End Skip ---

    // -----------------------------------------------------------------------
    // 1. Run the shell script so libverushash.a exists (ONLY for SBF target)
    // -----------------------------------------------------------------------
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let script = crate_dir.join("build.sh");

    // Ensure the script is executable before running
    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&script)
            .expect("build.sh not found")
            .permissions();
        if perms.mode() & 0o111 == 0 {
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
                .expect("Failed to set build.sh executable");
        }
    }

    // OUT_DIR is set by Cargo and is where the script should place the library.
    // Pass it as an environment variable to the script.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Prepare the command to run build.sh
    let mut command = Command::new("bash");
    command.arg(&script);
    command.env("OUT_DIR", &out_dir); // Pass OUT_DIR to the script

    // Explicitly forward CC and CXX from the build environment to the script's environment.
    // cargo build-sbf should set these to the Solana SDK's clang/clang++.
    let cc = env::var("CC").ok();
    let cxx = env::var("CXX").ok();
    if let Some(ref cc_val) = cc {
        command.env("CC", cc_val);
    }
    if let Some(ref cxx_val) = cxx {
        command.env("CXX", cxx_val);
    }
    // Note: CFLAGS/CXXFLAGS are handled within build.sh by appending to existing env vars.

    // Execute the build script
    let status = command.status().expect("failed to run build.sh");

    if !status.success() {
        // Attempt to capture and print output on failure
        // Prepare a separate command for capturing output, also passing env vars
        let mut error_command = Command::new("bash");
        error_command.arg(&script);
        error_command.env("OUT_DIR", &out_dir);
        if let Some(ref cc_val) = cc {
            error_command.env("CC", cc_val);
        }
        if let Some(ref cxx_val) = cxx {
            error_command.env("CXX", cxx_val);
        }

        let output = error_command
            .output()
            .expect("Failed to capture build.sh output on error");
        println!(
            "build.sh failed with status: {}\nstdout:\n{}\nstderr:\n{}",
            status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        panic!("build.sh failed");
    }

    // -----------------------------------------------------------------------
    // 2. Tell Cargo where to find and how to link the static lib (ONLY for SBF)
    // -----------------------------------------------------------------------
    // The library `libverushash.a` should now be in `OUT_DIR`.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=verushash");

    // IMPORTANT: **do NOT link the system C++ std-lib** – it does not exist in
    //             the Solana BPF loader.
    // println!("cargo:rustc-link-lib=c++");

    // Re-run this script if C/C++ sources change (still relevant for SBF)
    // Add paths relative to CARGO_MANIFEST_DIR (verus crate root)
    println!("cargo:rerun-if-changed=vendor/veruscoin/src/crypto/verus_hash.cpp");
    println!("cargo:rerun-if-changed=vendor/veruscoin/src/crypto/verus_hash.h");
    println!("cargo:rerun-if-changed=vendor/veruscoin/src/crypto/haraka_portable.c");
    println!("cargo:rerun-if-changed=vendor/veruscoin/src/crypto/haraka256_portable.c");
    println!("cargo:rerun-if-changed=vendor/veruscoin/src/crypto/haraka512_portable.c");
    // Add other C/C++ source files listed in build.sh if they exist

    // Note: The rerun-if-changed for build.sh is now outside this SBF-only block
    // to ensure Cargo re-evaluates build.rs correctly on host targets too.
    // The linking instructions above are now correctly inside the SBF-only block.
}
