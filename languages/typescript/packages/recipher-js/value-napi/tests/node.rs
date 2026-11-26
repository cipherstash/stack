//! Exercise live N-API conversions, including in package-scoped mutation runs.

/// A directory of this run's own under the build directory, removed when
/// the run ends.
struct Stage(std::path::PathBuf);

impl Stage {
    fn new(target: &std::path::Path) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = target.join(format!("run-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the run's directory");
        Self(dir)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn node_value_conformance() {
    use std::{path::Path, process::Command};
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = package.parent().expect("workspace");
    let addon = package.join("tests/addon/Cargo.toml");
    let target = workspace.join("target/napi-test-addon");
    let build = Command::new(env!("CARGO"))
        .args(["build", "--locked", "--quiet", "--manifest-path"])
        .arg(addon)
        .arg("--target-dir")
        .arg(&target)
        .output()
        .expect("run Cargo for the test addon");
    assert!(
        build.status.success(),
        "addon build: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let library = target.join("debug").join(format!(
        "{}recipher_value_napi_test_addon{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    // The build is shared, and Cargo locks it; the files Node loads are
    // staged per run, so a concurrent run cannot rewrite them mid-load.
    let stage = Stage::new(&target);
    let module = stage.0.join("addon.node");
    std::fs::copy(library, &module).expect("copy Node module");
    let example = include_str!("../README.md")
        .split_once("```javascript\n")
        .expect("README JavaScript example")
        .1
        .split_once("\n```")
        .expect("end of README JavaScript example")
        .0;
    let example_path = stage.0.join("readme-example.cjs");
    std::fs::write(&example_path, example).expect("write README example");
    for suite in [
        "tests/value-conformance.cjs",
        "tests/object-safety.cjs",
        "tests/kind_inventory.cjs",
        "tests/encrypt.cjs",
        "tests/frames.cjs",
    ]
    .map(|suite| package.join(suite))
    .into_iter()
    .chain([example_path])
    {
        let result = Command::new("node")
            .arg(&suite)
            .arg(&module)
            .output()
            .expect("Node.js is required for binding tests");
        assert!(
            result.status.success(),
            "{}:\n{}\n{}",
            suite.display(),
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
