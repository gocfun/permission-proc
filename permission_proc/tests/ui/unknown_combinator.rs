include!("../support/common.rs");
use permission_proc::permission;

#[permission(either("a", "b"))]
fn handler(claims: Claims) -> Result<(), ()> {
    let _ = claims;
    Ok(())
}

fn main() {}
