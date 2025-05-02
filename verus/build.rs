use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    // 1. Generate Haraka constants using a helper C program (runs on host)
    //    We do this *before* calling build.sh so the .inc file exists.
    // -----------------------------------------------------------------------
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let constants_inc_path = out_dir.join("haraka_rc_vrsc.inc");
    let generator_src_path = crate_dir.join("c").join("generate_constants.c");
    let generator_exe_path = out_dir.join("generate_constants");

    println!(
        "cargo:info=Compiling constants generator: {}",
        generator_src_path.display()
    );

    // Compile generate_constants.c using the host C compiler, then link it.
    // let host_triple = env::var("HOST").expect("HOST environment variable not set"); // Not needed for direct clang call
    let generator_obj_path = out_dir.join("generate_constants.o"); // Define object path
                                                                   // Note: generator_exe_path is already defined earlier

    // Step 1: Compile generate_constants.c to an object file using the host compiler directly
    println!(
        "cargo:info=Compiling constants generator source: {}",
        generator_src_path.display()
    );
    let compile_status = Command::new("clang") // Use host clang directly
        .arg("-c") // Compile only flag
        .arg(&generator_src_path) // Input C file
        .arg("-o") // Output flag
        .arg(&generator_obj_path) // Specify object file output path
        .arg("-O2") // Add optimization
        // Add host target flags if necessary (e.g., for macOS)
        // .arg(format!("--target={}", host_triple)) // Might be needed
        .status()
        .expect("Failed to invoke host compiler (clang) for constants generator source");

    if !compile_status.success() {
        panic!(
            "Failed to compile constants generator source: {}",
            compile_status
        );
    }

    // Step 2: Link the object file into an executable using the host linker (clang)
    println!(
        "cargo:info=Linking constants generator object: {}",
        generator_obj_path.display()
    );
    let link_status = Command::new("clang") // Use host clang for linking
        .arg(&generator_obj_path)
        .arg("-o") // Output flag
        .arg(&generator_exe_path) // Specify executable output path
        .status()
        .expect("Failed to invoke host linker (clang) for constants generator");

    if !link_status.success() {
        panic!(
            "Failed to link constants generator executable: {}",
            link_status
        );
    }

    // Step 3: Run the linked executable
    println!(
        "cargo:info=Running constants generator: {}",
        generator_exe_path.display()
    );
    let generator_cmd = Command::new(&generator_exe_path) // Use the correct path to the linked exe
        .stdout(Stdio::piped()) // Capture stdout
        .stderr(Stdio::piped()) // Capture stderr
        .spawn()
        .expect("Failed to spawn linked constants generator"); // Should find the exe now

    let output = generator_cmd
        .wait_with_output()
        .expect("Failed to wait for constants generator");

    if !output.status.success() {
        eprintln!(
            "Constants generator failed with status: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        panic!("Constants generator failed");
    }

    // Write the captured stdout (the constants) to the .inc file in OUT_DIR
    println!(
        "cargo:info=Writing generated constants to: {}",
        constants_inc_path.display()
    );
    let mut file =
        fs::File::create(&constants_inc_path).expect("Failed to create constants include file");
    file.write_all(&output.stdout)
        .expect("Failed to write constants include file");

    // Also copy the generated constants file into the C source directory (`verus/c/`)
    // so that `#include "haraka_rc_vrsc.inc"` in `haraka_portable.c` can find it
    // reliably during both host and SBF builds, without relying on OUT_DIR include paths.
    let constants_dest_path = crate_dir.join("c").join("haraka_rc_vrsc.inc");
    println!(
        "cargo:info=Copying generated constants from {} to {}",
        constants_inc_path.display(),
        constants_dest_path.display()
    );
    fs::copy(&constants_inc_path, &constants_dest_path)
        .expect("Failed to copy constants include file to c/");

    // Tell cargo to rerun if the generator source changes
    println!("cargo:rerun-if-changed={}", generator_src_path.display());
    // Note: build.rs changes automatically trigger rerun.

    // -----------------------------------------------------------------------
    // Run the shell script so libverushash.a exists (for SBF or host+portable)
    //    This script will now use the generated constants file.
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
    // 2. Tell Cargo where to find and how to link the static lib (if built)
    // -----------------------------------------------------------------------
    // The library `libverushash.a` should now be in `OUT_DIR`.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=verushash");

    // IMPORTANT: **do NOT link the system C++ std-lib when building for SBF**
    // It's okay (and usually necessary) to link it for host builds.
    // However, the Rust linker seems to handle this automatically for host builds.
    // Explicitly linking `libc++` might be needed on some systems if linking fails.
    // if !target.contains("sbf") && !target.contains("bpf") {
    //     println!("cargo:rustc-link-lib=c++");
    // }

    // Re-run this script if C/C++ sources change
    // Add paths relative to CARGO_MANIFEST_DIR (verus crate root) using the 'c' directory
    println!("cargo:rerun-if-changed=c/verus_hash.cpp");
    println!("cargo:rerun-if-changed=c/verus_hash.h");
    println!("cargo:rerun-if-changed=c/haraka_portable.c"); // This now includes the generated constants
    println!("cargo:rerun-if-changed=c/haraka_portable.h");
    println!("cargo:rerun-if-changed=c/common.h");
    println!("cargo:rerun-if-changed=c/uint256.cpp");
    println!("cargo:rerun-if-changed=c/uint256.h");
    println!("cargo:rerun-if-changed=c/verus_clhash.h");
    // No need to rerun if haraka_constants.c changes, as it's effectively empty.
    // No need to rerun if haraka_rc_vrsc.inc changes, as it's in OUT_DIR and generated by this script.
    // Rerun for the generator source is handled above.

    // Re-run if the build script itself changes
    println!("cargo:rerun-if-changed=build.sh");

    // Note: The rerun-if-changed for build.sh ensures Cargo re-evaluates build.rs
    // correctly on all targets.
    // Rerun if feature flags change as well.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PORTABLE");
}
