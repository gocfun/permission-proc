include!("../support/common.rs");
use permission_proc::permission;

#[permission("a")]
fn handler(a: Claims, b: Claims) -> Result<(), ()> {
    let _ = (a, b);
    Ok(())
}

fn main() {}
