//! Exercise the regeneration guard without ever reaching a fixture writer.
mod common;

#[test]
fn fixture_update_probe() {
    if let Ok(expected) = std::env::var("STACK_FIXTURE_GUARD_PROBE") {
        assert_eq!(
            common::fixture_updates_requested_or_panic(),
            expected == "true"
        );
    }
}

#[test]
fn required_conformance_refuses_fixture_updates() {
    for required in [None, Some("0"), Some("1")] {
        for update in [None, Some(""), Some("1")] {
            let mut command =
                std::process::Command::new(std::env::current_exe().expect("test binary"));
            command
                .args(["--exact", "fixture_update_probe", "--nocapture"])
                .env_remove("STACK_CONFORMANCE_REQUIRED")
                .env_remove("STACK_ENCRYPT_UPDATE_FIXTURES")
                .env("STACK_FIXTURE_GUARD_PROBE", update.is_some().to_string());
            if let Some(value) = required {
                command.env("STACK_CONFORMANCE_REQUIRED", value);
            }
            if let Some(value) = update {
                command.env("STACK_ENCRYPT_UPDATE_FIXTURES", value);
            }
            let output = command.output().expect("run fixture guard probe");
            let refused = required == Some("1") && update.is_some();
            assert_eq!(
                output.status.success(),
                !refused,
                "required={required:?}, update={update:?}: {output:?}"
            );
            if refused {
                assert!(String::from_utf8_lossy(&output.stderr)
                    .contains("conformance checks must not update frozen fixtures"));
            }
        }
    }
}
