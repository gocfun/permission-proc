include!("../support/common.rs");
use permission_proc::permission;

#[permission("a")]
fn handler(id: u64) -> Result<(), ()> {
    let _ = id;
    Ok(())
}

fn main() {}
