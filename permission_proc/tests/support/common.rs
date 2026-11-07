// Shared by the UI tests through `include!`.
use permission_proc::{Permissions, Requirement};

pub struct Claims;

impl Permissions for Claims {
    type Rejection = ();
    fn has_permission(&self, _: &str) -> bool {
        true
    }
    fn permission_denied(&self, _: &Requirement) {}
}
