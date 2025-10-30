use std::{env, fs, process::Command};

fn emit_version() {
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let package_version = env::var("CARGO_PKG_VERSION").unwrap();

    let git_commit_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .inspect_err(|_e| {
            println!("cargo:warning=git rev-parse failure, unable to determine revision");
        })
        .map(|cmd| String::from_utf8(cmd.stdout).unwrap().trim_end().into())
        .unwrap_or("unknown-rev".to_string());

    let release_name = format!("{package_name}@{package_version}+{git_commit_sha}");
    fs::write("./VERSION", &release_name).expect("Unable to write version");
    println!("cargo:rustc-env=SENTRY_MIRROR_VERSION={}", &release_name);
}

fn main() {
    emit_version();
}
