include!("../support/common.rs");
use permission_proc::permission;

#[permission]
fn handler(claims: Claims) -> Result<(), ()> {
    let _ = claims;
    Ok(())
}

fn main() {}
