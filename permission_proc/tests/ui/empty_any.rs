include!("../support/common.rs");
use permission_proc::permission;

#[permission(any())]
fn handler(claims: Claims) -> Result<(), ()> {
    let _ = claims;
    Ok(())
}

fn main() {}
