use std::ops::Deref;

use permission_proc::{permission, Permissions, Requirement};

#[derive(Clone)]
struct Claims {
    permissions: Vec<&'static str>,
}

impl Claims {
    fn with(permissions: &[&'static str]) -> Self {
        Claims {
            permissions: permissions.to_vec(),
        }
    }

    // An inherent method with the same name as a trait method must not be
    // picked up by the generated code.
    #[allow(dead_code)]
    fn satisfies(&self, _: &Requirement) -> bool {
        true
    }
}

#[derive(Debug, PartialEq)]
struct Denied(String);

impl Permissions for Claims {
    type Rejection = Denied;

    fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission)
    }

    fn permission_denied(&self, requirement: &Requirement) -> Denied {
        Denied(requirement.to_string())
    }
}

/// Stand-in for axum's `Extension<T>`.
struct Extension<T>(T);

impl<T> Deref for Extension<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

#[derive(Debug, PartialEq)]
enum Response {
    Ok(&'static str),
    Forbidden(String),
}

impl From<Denied> for Response {
    fn from(denied: Denied) -> Self {
        Response::Forbidden(denied.0)
    }
}

#[permission("posts:read")]
fn plain_binding(claims: Claims) -> Result<&'static str, Denied> {
    let _ = claims;
    Ok("read")
}

#[test]
fn result_return_type_gets_err() {
    assert_eq!(plain_binding(Claims::with(&["posts:read"])), Ok("read"));
    assert_eq!(
        plain_binding(Claims::with(&[])),
        Err(Denied("posts:read".into()))
    );
}

#[permission("posts:write")]
fn tuple_struct_pattern(Extension(_claims): Extension<Claims>, body: &'static str) -> Response {
    Response::Ok(body)
}

#[test]
fn non_result_return_type_uses_into() {
    let allowed = Extension(Claims::with(&["posts:write"]));
    assert_eq!(tuple_struct_pattern(allowed, "hi"), Response::Ok("hi"));
    let denied = Extension(Claims::with(&["posts:read"]));
    assert_eq!(
        tuple_struct_pattern(denied, "hi"),
        Response::Forbidden("posts:write".into())
    );
}

#[permission("posts:write")]
fn wrapper_binding(claims: Extension<Claims>) -> Response {
    let _ = claims;
    Response::Ok("ok")
}

#[permission("posts:write")]
fn reference_binding(claims: &Claims) -> Response {
    let _ = claims;
    Response::Ok("ok")
}

#[test]
fn auto_derefs_wrappers_and_references() {
    let claims = Claims::with(&["posts:write"]);
    assert_eq!(
        wrapper_binding(Extension(claims.clone())),
        Response::Ok("ok")
    );
    assert_eq!(reference_binding(&claims), Response::Ok("ok"));
    assert_eq!(
        reference_binding(&Claims::with(&[])),
        Response::Forbidden("posts:write".into())
    );
}

#[permission(any("posts:admin", all("posts:write", "posts:publish")))]
fn nested(claims: Claims) -> Result<(), Denied> {
    let _ = claims;
    Ok(())
}

#[test]
fn nested_requirements() {
    assert!(nested(Claims::with(&["posts:admin"])).is_ok());
    assert!(nested(Claims::with(&["posts:write", "posts:publish"])).is_ok());
    assert_eq!(
        nested(Claims::with(&["posts:write"])),
        Err(Denied(
            "any(posts:admin, all(posts:write, posts:publish))".into()
        ))
    );
}

struct User(Claims);

impl Permissions for User {
    type Rejection = Denied;
    fn has_permission(&self, permission: &str) -> bool {
        self.0.has_permission(permission)
    }
    fn permission_denied(&self, requirement: &Requirement) -> Denied {
        Denied(format!("user lacks {requirement}"))
    }
}

#[permission("a")]
fn marked_argument(#[claims] user: User, other: Claims) -> Result<(), Denied> {
    let _ = (user, other);
    Ok(())
}

#[permission("a", claims = user)]
fn explicit_argument(other: Claims, user: User) -> Result<(), Denied> {
    let _ = (user, other);
    Ok(())
}

#[test]
fn choosing_the_claims_argument() {
    let user = || User(Claims::with(&[]));
    let other = || Claims::with(&["a"]);
    assert_eq!(
        marked_argument(user(), other()),
        Err(Denied("user lacks a".into()))
    );
    assert_eq!(
        explicit_argument(other(), user()),
        Err(Denied("user lacks a".into()))
    );
}

type ApiResult<T> = std::result::Result<T, Denied>;

#[permission("a", result = true)]
fn result_alias(claims: Claims) -> ApiResult<()> {
    let _ = claims;
    Ok(())
}

#[permission("a", result = false)]
fn result_disabled(claims: Claims) -> Result<(), Denied> {
    let _ = claims;
    Ok(())
}

impl From<Denied> for Result<(), Denied> {
    fn from(denied: Denied) -> Self {
        Err(Denied(format!("converted {}", denied.0)))
    }
}

#[test]
fn result_option_overrides_detection() {
    assert_eq!(result_alias(Claims::with(&[])), Err(Denied("a".into())));
    assert_eq!(
        result_disabled(Claims::with(&[])),
        Err(Denied("converted a".into()))
    );
}

struct Service {
    name: &'static str,
}

impl Service {
    #[permission("svc:call")]
    fn call(&self, claims: &Claims) -> Result<&'static str, Denied> {
        let _ = claims;
        Ok(self.name)
    }

    #[permission("svc:call")]
    async fn call_async(&self, claims: Claims) -> Result<&'static str, Denied> {
        let _ = claims;
        Ok(self.name)
    }
}

#[tokio::test]
async fn methods_and_async_functions() {
    let service = Service { name: "svc" };
    let allowed = Claims::with(&["svc:call"]);
    assert_eq!(service.call(&allowed), Ok("svc"));
    assert_eq!(service.call_async(allowed).await, Ok("svc"));
    assert!(service.call_async(Claims::with(&[])).await.is_err());
}

mod reexport {
    pub use permission_proc as renamed;
}

#[permission("a", crate = reexport::renamed)]
fn custom_crate_path(claims: Claims) -> Result<(), Denied> {
    let _ = claims;
    Ok(())
}

#[test]
fn crate_option() {
    assert!(custom_crate_path(Claims::with(&["a"])).is_ok());
}

/// Docs and other attributes on the function survive expansion.
#[permission("a")]
#[must_use]
fn keeps_attributes(claims: Claims) -> Result<(), Denied> {
    let _ = claims;
    Ok(())
}

#[test]
fn attributes_are_preserved() {
    let _ = keeps_attributes(Claims::with(&["a"]));
}
