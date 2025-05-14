use std::env;
// fs and Write are no longer used directly in this simplified build script
// use std::fs;
// use std::io::Write;
use std::path::PathBuf;
use std::process::Command; // Stdio is no longer used directly

// Use the `cc` crate to compile the generator helper
extern crate cc;

fn main() {
    // Get the target architecture from the environment variable set by Cargo
    let target = env::var("TARGET").unwrap();
    let portable_enabled = env::var("CARGO_FEATURE_PORTABLE").is_ok();

    // --- Skip C/C++ build ONLY if target is not SBF/BPF AND 'portable' feature is disabled ---
    // We need to build the C library if:
    // 1. Target is SBF/BPF OR
    // 2. Target is host AND 'portable' feature is enabled (for tests, etc.)
    if !target.contains("sbf") && !target.contains("bpf") && !portable_enabled {
        println!(
            "cargo:info=Skipping verus C/C++ build for host target without 'portable' feature: {}",
            target
        );
        // Still need to rerun if build script changes
        println!("cargo:rerun-if-changed=build.sh");
        // Also rerun if feature flags change
        println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PORTABLE");
        return; // Exit early, do not proceed with C build or linking
    }

    if portable_enabled && !target.contains("sbf") && !target.contains("bpf") {
        println!(
            "cargo:info=Building verus C/C++ library for host target ({}) because 'portable' feature is enabled...",
            target
        );
    } else {
        println!(
            "cargo:info=Building verus C/C++ library for SBF target ({})",
            target
        );
    }
    // --- End Skip ---

    // -----------------------------------------------------------------------
    // Constants are now hardcoded in verus/c/haraka_portable.c
    // The generation step via generate_constants.c is removed.
    // -----------------------------------------------------------------------
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let _out_dir = PathBuf::from(env::var("OUT_DIR").unwrap()); // Prefixed with _ as it's not directly used later by this name

    // VERUS_BPF_TARGET define for C/C++ is handled when setting CFLAGS/CXXFLAGS for build.sh
    // VERUS_BPF_TARGET cfg for Rust is handled when setting rustc-cfg for build.sh

    // -----------------------------------------------------------------------
    // Run the shell script so libverushash.a exists (for SBF or host+portable)
    // -----------------------------------------------------------------------
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
    let out_dir_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Prepare the command to run build.sh
    let mut command = Command::new("bash");
    command.arg(&script);
    command.env("OUT_DIR", &out_dir_path); // Pass OUT_DIR to the script

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

    // Add VERUS_BPF_TARGET define if building for BPF/SBF
    // Also, SBF/BPF implies forcing portable C implementations.
    // If 'portable' feature is enabled for host, also force portable C.
    let mut cflags_to_add = Vec::new();
    let mut cxxflags_to_add = Vec::new();

    if target.contains("sbf") || target.contains("bpf") {
        cflags_to_add.push("-DVERUS_BPF_TARGET=1".to_string());
        cxxflags_to_add.push("-DVERUS_BPF_TARGET=1".to_string());
        // For SBF/BPF, VERUS_FORCE_PORTABLE_IMPL is effectively true and handled by build.sh
        // build.sh will add -DVERUS_FORCE_PORTABLE_IMPL=1 for BPF targets
        println!("cargo:rustc-cfg=verus_bpf_target");
        // Pass this info to build.sh too
        command.env("BUILD_RS_TARGET_IS_BPF", "1");
    } else if portable_enabled {
        // Host target with 'portable' feature enabled
        // Signal build.sh to use portable C implementations
        command.env("BUILD_RS_REQUESTS_PORTABLE_C_IMPL", "1");
        // build.sh will be responsible for adding -DVERUS_FORCE_PORTABLE_IMPL=1
    }
    // Note: If host and portable is NOT enabled, IsCPUVerusOptimized() will take effect.

    // Append any general flags if needed (currently none specific here, handled by build.sh)
    let current_cflags = env::var("CFLAGS").unwrap_or_default();
    let new_cflags = format!("{} {}", current_cflags, cflags_to_add.join(" ")); // cflags_to_add might be empty for host
    command.env("CFLAGS", new_cflags.trim());

    let current_cxxflags = env::var("CXXFLAGS").unwrap_or_default();
    let new_cxxflags = format!("{} {}", current_cxxflags, cxxflags_to_add.join(" ")); // cxxflags_to_add might be empty for host
    command.env("CXXFLAGS", new_cxxflags.trim());

    // Execute the build script
    let status = command.status().expect("failed to run build.sh");

    if !status.success() {
        // Attempt to capture and print output on failure
        // Prepare a separate command for capturing output, also passing env vars
        let mut error_command = Command::new("bash");
        error_command.arg(&script);
        error_command.env("OUT_DIR", &out_dir_path); // Using out_dir_path
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
    // 2. Tell Cargo where to find and how to link the static lib (if built)
    // -----------------------------------------------------------------------
    // The library `libverushash.a` should now be in `OUT_DIR`.
    println!("cargo:rustc-link-search=native={}", out_dir_path.display()); // Using out_dir_path
    println!("cargo:rustc-link-lib=static=verushash");

    // IMPORTANT: **do NOT link the system C++ std-lib when building for SBF**
    // It's okay (and usually necessary) to link it for host builds.
    if !target.contains("sbf") && !target.contains("bpf") {
        if target.contains("apple-darwin") {
            println!("cargo:rustc-link-lib=c++");
        } else {
            // For other non-SBF systems like Linux, it's typically libstdc++
            println!("cargo:rustc-link-lib=stdc++");
        }
    }

    // Re-run this script if C/C++ sources change
    // Add paths relative to CARGO_MANIFEST_DIR (verus crate root) using the 'c' directory
    println!("cargo:rerun-if-changed=c/verus_hash.cpp");
    println!("cargo:rerun-if-changed=c/verus_hash.h");
    println!("cargo:rerun-if-changed=c/haraka_portable.c"); // Now includes hardcoded constants
    println!("cargo:rerun-if-changed=c/haraka_portable.h");
    println!("cargo:rerun-if-changed=c/common.h");
    println!("cargo:rerun-if-changed=c/uint256.cpp");
    println!("cargo:rerun-if-changed=c/uint256.h");
    println!("cargo:rerun-if-changed=c/verus_clhash.h");
    println!("cargo:rerun-if-changed=c/verus_clhash_portable.cpp");

    // Re-run if the build script itself changes
    println!("cargo:rerun-if-changed=build.sh");

    // Note: The rerun-if-changed for build.sh ensures Cargo re-evaluates build.rs
    // correctly on all targets.
    // Rerun if feature flags change as well.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PORTABLE");
}
