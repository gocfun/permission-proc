//! Declarative permission checks for Rust functions and web handlers.
//!
//! Put `#[permission("...")]` on a function, tell the crate how to read
//! permissions from your claims type, and the check runs before the
//! function body:
//!
//! ```
//! use permission_proc::{permission, Permissions, Requirement};
//!
//! struct Claims {
//!     permissions: Vec<String>,
//! }
//!
//! #[derive(Debug, PartialEq)]
//! struct Forbidden(String);
//!
//! impl Permissions for Claims {
//!     type Rejection = Forbidden;
//!
//!     fn has_permission(&self, permission: &str) -> bool {
//!         self.permissions.iter().any(|p| p == permission)
//!     }
//!
//!     fn permission_denied(&self, requirement: &Requirement) -> Forbidden {
//!         Forbidden(format!("missing permission: {requirement}"))
//!     }
//! }
//!
//! #[permission("posts:delete")]
//! fn delete_post(claims: Claims, id: u64) -> Result<u64, Forbidden> {
//!     Ok(id)
//! }
//!
//! let admin = Claims { permissions: vec!["posts:delete".into()] };
//! let guest = Claims { permissions: vec![] };
//!
//! assert_eq!(delete_post(admin, 7), Ok(7));
//! assert_eq!(
//!     delete_post(guest, 7),
//!     Err(Forbidden("missing permission: posts:delete".into())),
//! );
//! ```
//!
//! # Requirements
//!
//! The first argument of the attribute describes what is required. It can
//! be a single permission or a combination built with `any(...)` and
//! `all(...)`, which can be nested:
//!
//! ```text
//! #[permission("posts:read")]
//! #[permission(any("posts:read", "posts:admin"))]
//! #[permission(all("posts:write", any("team:editor", "team:owner")))]
//! ```
//!
//! # Finding the claims argument
//!
//! The macro needs to know which argument holds the claims. In order of
//! priority:
//!
//! 1. `claims = name` in the attribute, where `name` is a binding introduced
//!    by one of the arguments: `#[permission("a", claims = user)]`.
//! 2. An argument marked with `#[claims]`:
//!    `fn f(#[claims] user: User)`.
//! 3. Otherwise, the single argument whose type mentions a type whose name
//!    ends in `Claims` (`Claims`, `JwtClaims`, `Extension<Claims>`,
//!    `&MyClaims`, ...).
//!
//! The argument may be a plain binding (`claims: Claims`) or a single-field
//! tuple struct pattern (`Extension(claims): Extension<Claims>`). Wrapper
//! types that implement [`Deref`](core::ops::Deref) to the claims type, such
//! as axum's `Extension`, work without extra code.
//!
//! # What a denied call returns
//!
//! When the check fails the function returns early with
//! [`Permissions::permission_denied`], converted with [`Into`]:
//!
//! * If the declared return type is written as `Result<..>` (any path ending
//!   in `Result`), the function returns `Err(rejection.into())`.
//! * Otherwise it returns `rejection.into()`.
//!
//! Override the detection with `result = true` or `result = false`, for
//! example when the return type is a type alias such as `ApiResult<T>`.
//!
//! Functions returning `impl Trait` cannot use [`Into`] inference. Make the
//! rejection type the concrete type the function returns, or return a named
//! type.
//!
//! # Re-exporting
//!
//! If you re-export this crate under another path, tell the macro where to
//! find it with `crate = path::to::permission_proc`.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;

/// Guards a function with a permission check.
///
/// See the [crate-level documentation](crate) for the full syntax.
pub use permission_proc_macros::permission;

/// Access to the permissions carried by a claims or principal type.
///
/// Implement this for the type that holds the caller's identity (usually
/// the decoded token claims). [`#[permission]`](permission) calls it before
/// running the guarded function.
pub trait Permissions {
    /// Value produced when the caller lacks the required permissions.
    ///
    /// The macro converts it into the guarded function's return type with
    /// [`Into`] (or into the error type when the function returns a
    /// `Result`).
    type Rejection;

    /// Returns `true` if the caller holds `permission`.
    fn has_permission(&self, permission: &str) -> bool;

    /// Builds the rejection returned when `requirement` is not satisfied.
    fn permission_denied(&self, requirement: &Requirement) -> Self::Rejection;

    /// Returns `true` if the caller satisfies `requirement`.
    ///
    /// The default implementation evaluates the requirement with
    /// [`has_permission`](Permissions::has_permission). Override it if you
    /// can answer more efficiently, for example with wildcard matching.
    fn satisfies(&self, requirement: &Requirement) -> bool {
        requirement.is_satisfied_by(|permission| self.has_permission(permission))
    }
}

impl<P: Permissions + ?Sized> Permissions for &P {
    type Rejection = P::Rejection;

    fn has_permission(&self, permission: &str) -> bool {
        (**self).has_permission(permission)
    }

    fn permission_denied(&self, requirement: &Requirement) -> Self::Rejection {
        (**self).permission_denied(requirement)
    }

    fn satisfies(&self, requirement: &Requirement) -> bool {
        (**self).satisfies(requirement)
    }
}

/// A permission requirement declared with [`#[permission]`](permission).
///
/// `Display` renders it in the same syntax the attribute uses, for example
/// `posts:read` or `any(posts:read, posts:admin)`, which makes it
/// convenient for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Requirement {
    /// A single permission.
    Permission(&'static str),
    /// At least one of the nested requirements.
    Any(&'static [Requirement]),
    /// Every nested requirement.
    All(&'static [Requirement]),
}

impl Requirement {
    /// Evaluates the requirement, asking `has_permission` about each
    /// permission it mentions. Evaluation short-circuits.
    pub fn is_satisfied_by<F>(&self, mut has_permission: F) -> bool
    where
        F: FnMut(&str) -> bool,
    {
        self.eval(&mut has_permission)
    }

    fn eval<F>(&self, has_permission: &mut F) -> bool
    where
        F: FnMut(&str) -> bool,
    {
        match self {
            Requirement::Permission(permission) => has_permission(permission),
            Requirement::Any(requirements) => requirements.iter().any(|r| r.eval(has_permission)),
            Requirement::All(requirements) => requirements.iter().all(|r| r.eval(has_permission)),
        }
    }

    /// Calls `f` for every permission mentioned by the requirement, in
    /// declaration order.
    pub fn for_each_permission<F>(&self, mut f: F)
    where
        F: FnMut(&'static str),
    {
        self.visit(&mut f);
    }

    fn visit<F>(&self, f: &mut F)
    where
        F: FnMut(&'static str),
    {
        match self {
            Requirement::Permission(permission) => f(permission),
            Requirement::Any(requirements) | Requirement::All(requirements) => {
                for requirement in *requirements {
                    requirement.visit(f);
                }
            }
        }
    }
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, requirements) = match self {
            Requirement::Permission(permission) => return f.write_str(permission),
            Requirement::Any(requirements) => ("any", requirements),
            Requirement::All(requirements) => ("all", requirements),
        };
        write!(f, "{name}(")?;
        for (i, requirement) in requirements.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(requirement, f)?;
        }
        f.write_str(")")
    }
}

/// Implementation details used by the generated code. Not public API.
#[doc(hidden)]
pub mod __private {
    use super::{Permissions, Requirement};

    /// Extension trait with names that will not clash with inherent methods
    /// on the user's claims type. Method-call syntax lets the generated code
    /// auto-deref through wrappers such as `Extension<Claims>`.
    pub trait PermissionProcExt: Permissions {
        /// Returns the rejection if `requirement` is not satisfied.
        #[inline]
        fn __permission_proc_check(&self, requirement: &Requirement) -> Option<Self::Rejection> {
            if Permissions::satisfies(self, requirement) {
                None
            } else {
                Some(Permissions::permission_denied(self, requirement))
            }
        }
    }

    impl<P: Permissions + ?Sized> PermissionProcExt for P {}
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::Requirement::{self, All, Any, Permission};
    use std::{string::ToString, vec::Vec};

    const NESTED: Requirement = All(&[Permission("a"), Any(&[Permission("b"), Permission("c")])]);

    fn holding(held: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |p| held.contains(&p)
    }

    #[test]
    fn single_permission() {
        assert!(Permission("a").is_satisfied_by(holding(&["a"])));
        assert!(!Permission("a").is_satisfied_by(holding(&["b"])));
    }

    #[test]
    fn nested_requirements() {
        assert!(NESTED.is_satisfied_by(holding(&["a", "c"])));
        assert!(!NESTED.is_satisfied_by(holding(&["a"])));
        assert!(!NESTED.is_satisfied_by(holding(&["b", "c"])));
    }

    #[test]
    fn empty_combinators() {
        assert!(All(&[]).is_satisfied_by(holding(&[])));
        assert!(!Any(&[]).is_satisfied_by(holding(&["a"])));
    }

    #[test]
    fn evaluation_short_circuits() {
        let mut asked = Vec::new();
        Any(&[Permission("a"), Permission("b")]).is_satisfied_by(|p| {
            asked.push(p.to_string());
            true
        });
        assert_eq!(asked, ["a"]);
    }

    #[test]
    fn display_uses_attribute_syntax() {
        assert_eq!(Permission("posts:read").to_string(), "posts:read");
        assert_eq!(NESTED.to_string(), "all(a, any(b, c))");
    }

    #[test]
    fn for_each_permission_visits_in_order() {
        let mut seen = Vec::new();
        NESTED.for_each_permission(|p| seen.push(p));
        assert_eq!(seen, ["a", "b", "c"]);
    }
}
