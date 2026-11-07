// Compile-error snapshots include rustc's own notes, which change between
// compiler releases. They are generated with the toolchain pinned in CI and
// skipped on other versions. Regenerate with:
//
//     TRYBUILD=overwrite cargo +1.99 test --test ui
#[rustversion::attr(
    not(stable(1.99)),
    ignore = "UI snapshots are generated with Rust 1.99; run `cargo +1.99 test --test ui`"
)]
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
