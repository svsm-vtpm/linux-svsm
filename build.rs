extern crate bindgen;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LIBCRT_SRC: &str = "external/libcrt";
const LIBM_SRC: &str = "external/libm";
const WOLFSSL_SRC: &str = "external/wolfssl";
const MSTPM_SRC: &str = "external/ms-tpm-20-ref";
const BUILD_DIR: &str = "external/build";

struct CommandWithArgs<'a>(String, Vec<&'a str>);

fn build_library(src_dir: &str, commands: &Vec<CommandWithArgs>) {
    let pwd = env::current_dir().unwrap();

    env::set_current_dir(src_dir).expect("failed to cd to build directory");

    for cmd in commands {
        Command::new(&cmd.0)
            .args(&cmd.1)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap();
    }

    env::set_current_dir(pwd).expect("failed to cd to build directory");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=libtpm.h");

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let libcrt_src = format!("{}/{}", manifest_dir, LIBCRT_SRC);
    let libm_src = format!("{}/{}", manifest_dir, LIBM_SRC);
    let wolfssl_src = format!("{}/{}", manifest_dir, WOLFSSL_SRC);
    let mstpm_src = Path::new(&format!("{}/{}", manifest_dir, MSTPM_SRC)).join("TPMCmd");
    let build_dir = format!("{}/{}", manifest_dir, BUILD_DIR);

    // Create $(pwd)/external/build/
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");
    // Create $(pwd)/external/build/lib
    let build_lib = Path::new(&build_dir).join("lib");
    fs::create_dir_all(&build_lib).expect("Failed to create build directory");

    /*let build = |src_dir: &str, build_dir: &str| {
        let pwd = env::current_dir().unwrap();
        env::set_current_dir(src_dir).expect("failed to change to build directory");
        Command::new("make")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap();

        let input_dir = Path::new(src_dir);
        let output_fname = input_dir.file_name().unwrap().to_str().unwrap().to_owned() + ".a";
        let input_path = input_dir.join(&output_fname);
        let output_path = Path::new(build_dir).join("lib").join(&output_fname);
        fs::copy(input_path, output_path).unwrap();
        env::set_current_dir(pwd).expect("failed to cd to root directory");
    };*/

    let mut build_cmds_libcrt: Vec<CommandWithArgs> = Vec::new();
    let install_prefix = format!("PREFIX={}", build_lib.to_str().unwrap());
    build_cmds_libcrt.push(CommandWithArgs(
        "make".to_string(),
        ["install", &install_prefix].to_vec(),
    ));

    build_library(&libcrt_src, &build_cmds_libcrt);

    let mut build_cmds_libm: Vec<CommandWithArgs> = Vec::new();
    build_cmds_libm.push(CommandWithArgs(
        "make".to_string(),
        ["install", &install_prefix].to_vec(),
    ));

    build_library(&libm_src, &build_cmds_libm);

    //build(&libcrt_src, &build_dir);
    //build(&libm_src, &build_dir);

    let common_config_args = [
        "--enable-static",
        "--disable-shared",
        &format!("--prefix={}", build_dir),
    ];

    let wolfssl_cflags = format!(
        "-fno-stack-protector -fPIE -nostdinc -Wno-error=float-equal -I{} -I{} -I{}",
        Path::new(&wolfssl_src).join("amd-svsm").to_str().unwrap(),
        Path::new(&libcrt_src).join("include").to_str().unwrap(),
        Path::new(&libm_src).join("include").to_str().unwrap()
    );

    let wolfssl_ldflags = format!(
        "-L{} -lcrt -lm",
        Path::new(&build_dir).join("lib").to_str().unwrap()
    );

    let cflags = format!("CFLAGS={}", wolfssl_cflags);
    let ldflags = format!("LDFLAGS={}", wolfssl_ldflags);
    let mut wolfssl_config_args = common_config_args.to_vec();
    wolfssl_config_args.push("--enable-usersettings");
    wolfssl_config_args.push("--host=x86_64");
    wolfssl_config_args.push(&cflags);
    wolfssl_config_args.push(&ldflags);
    wolfssl_config_args.push("--disable-crypttests");
    wolfssl_config_args.push("--disable-examples");

    let mut build_cmds_wolfssl: Vec<CommandWithArgs> = Vec::new();
    build_cmds_wolfssl.push(CommandWithArgs("./autogen.sh".to_string(), Vec::new()));
    build_cmds_wolfssl.push(CommandWithArgs(
        "./configure".to_string(),
        wolfssl_config_args,
    ));
    build_cmds_wolfssl.push(CommandWithArgs("make".to_string(), Vec::new()));
    build_cmds_wolfssl.push(CommandWithArgs("make".to_string(), ["install"].to_vec()));

    build_library(&wolfssl_src, &build_cmds_wolfssl);

    let mstpm_cflags_inner = format!(
        "-fno-stack-protector -DSIMULATION=NO -DEPHEMERAL_NV -DVTPM -DWOLF_USER_SETTINGS -I{} -I{} -I{} -I{}",
        Path::new(&wolfssl_src).join("amd-svsm").to_str().unwrap(),
        Path::new(&libcrt_src).join("include").to_str().unwrap(),
        Path::new(&libm_src).join("include").to_str().unwrap(),
        Path::new(&build_dir).join("include").to_str().unwrap(),
    );

    let lcrypto_cflags_inner = format!(
        "-I{}",
        Path::new(&build_dir)
            .join("include")
            .join("wolfssl")
            .to_str()
            .unwrap()
    );

    let libs_inner = format!(
        "{} {}",
        Path::new(&build_dir)
            .join("lib")
            .join("libcrt.a")
            .to_str()
            .unwrap(),
        Path::new(&build_dir)
            .join("lib")
            .join("libm.a")
            .to_str()
            .unwrap()
    );

    let mstpm_cflags = format!("CFLAGS={}", mstpm_cflags_inner);
    let lcrypto_cflags = format!("LIBCRYPTO_CFLAGS={}", lcrypto_cflags_inner);
    let lcrypto_libs = format!(
        "LIBCRYPTO_LIBS={}",
        Path::new(&build_dir)
            .join("lib")
            .join("libwolfssl.a")
            .to_str()
            .unwrap()
    );
    let mstpm_libs = format!("LIBS={}", libs_inner);

    let mut mstpm_config_args = common_config_args.to_vec();
    mstpm_config_args.push("--with-crypto-engine=Wolf");
    mstpm_config_args.push(&mstpm_cflags);
    mstpm_config_args.push(&lcrypto_cflags);
    mstpm_config_args.push(&lcrypto_libs);
    mstpm_config_args.push(&mstpm_libs);

    let mut build_cmds_mstpm: Vec<CommandWithArgs> = Vec::new();
    build_cmds_mstpm.push(CommandWithArgs("./bootstrap".to_string(), Vec::new()));
    build_cmds_mstpm.push(CommandWithArgs(
        "./configure".to_string(),
        mstpm_config_args,
    ));

    build_cmds_mstpm.push(CommandWithArgs(
        "make".to_string(),
        ["Platform/src/libplatform.a"].to_vec(),
    ));
    build_cmds_mstpm.push(CommandWithArgs(
        "make".to_string(),
        ["tpm/src/libtpm.a"].to_vec(),
    ));

    build_cmds_mstpm.push(CommandWithArgs(
        "cp".to_string(),
        ["Platform/src/libplatform.a", build_lib.to_str().unwrap()].to_vec(),
    ));

    build_cmds_mstpm.push(CommandWithArgs(
        "cp".to_string(),
        ["tpm/src/libtpm.a", build_lib.to_str().unwrap()].to_vec(),
    ));

    build_library(&mstpm_src.to_str().unwrap(), &build_cmds_mstpm);

    let bindings = bindgen::Builder::default()
        .use_core()
        .ctypes_prefix("cty")
        .clang_arg("-DHASH_LIB=Wolf")
        .clang_arg("-DSYM_LIB=Wolf")
        .clang_arg("-DMATH_LIB=Wolf")
        .clang_arg(format!(
            "-I{}",
            Path::new(&wolfssl_src).join("amd-svsm").to_str().unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            Path::new(&build_dir).join("include").to_str().unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            mstpm_src.join("tpm").join("include").to_str().unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            mstpm_src
                .join("tpm")
                .join("include")
                .join("prototypes")
                .to_str()
                .unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            mstpm_src.join("Platform").join("include").to_str().unwrap()
        ))
        .clang_arg(format!(
            "-I{}",
            mstpm_src
                .join("Platform")
                .join("include")
                .join("prototypes")
                .to_str()
                .unwrap()
        ))
        .header("libtpm.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
