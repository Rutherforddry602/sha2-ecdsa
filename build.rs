use std::process::Command;

fn main() {
    #[cfg(feature = "cuda")]
    {
        println!("cargo:rerun-if-changed=src/gpu/cuda_kernel.cu");

        let out_dir = std::env::var("OUT_DIR").unwrap();
        let obj_path = format!("{}/cuda_kernel.o", out_dir);
        let lib_path = format!("{}/libcuda_kernel.a", out_dir);

        // Compile .cu to .o with nvcc
        let status = Command::new("nvcc")
            .args([
                "-c",
                "src/gpu/cuda_kernel.cu",
                "-o", &obj_path,
                "-O3",
                "--use_fast_math",
                "-Xcompiler", "-fPIC",
            ])
            .status()
            .expect("Failed to run nvcc. Is CUDA toolkit installed?");
        assert!(status.success(), "nvcc compilation failed");

        // Create static library
        let status = Command::new("ar")
            .args(["rcs", &lib_path, &obj_path])
            .status()
            .expect("Failed to run ar");
        assert!(status.success(), "ar failed");

        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=cuda_kernel");
        println!("cargo:rustc-link-search=native=/usr/local/cuda/lib64");
        println!("cargo:rustc-link-lib=cudart");
        println!("cargo:rustc-link-lib=stdc++");
    }
}
