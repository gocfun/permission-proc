include!("../support/common.rs");
use permission_proc::permission;

#[permission("a")]
fn handler(_: Claims) -> Result<(), ()> {
    Ok(())
}

fn main() {}
