include!("../support/common.rs");
use permission_proc::permission;

#[permission("a", claim = claims)]
fn handler(claims: Claims) -> Result<(), ()> {
    let _ = claims;
    Ok(())
}

fn main() {}
