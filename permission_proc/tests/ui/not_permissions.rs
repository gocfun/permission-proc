include!("../support/common.rs");
use permission_proc::permission;

struct NotClaims;

#[permission("a", claims = c)]
fn handler(c: NotClaims) -> Result<(), ()> {
    let _ = c;
    Ok(())
}

fn main() {}
