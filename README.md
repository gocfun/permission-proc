# permission_proc

[![crates.io](https://img.shields.io/crates/v/permission_proc.svg)](https://crates.io/crates/permission_proc)
[![docs.rs](https://docs.rs/permission_proc/badge.svg)](https://docs.rs/permission_proc)
[![CI](https://github.com/gocfun/permission-proc/actions/workflows/ci.yml/badge.svg)](https://github.com/gocfun/permission-proc/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/permission_proc.svg)](LICENSE)

Declarative permission checks for Rust functions and web handlers.

```rust
#[permission("posts:delete")]
async fn delete_post(Extension(claims): Extension<Claims>, Path(id): Path<u64>) -> Response {
    // only runs if `claims` holds "posts:delete"
}
```

- **Framework-agnostic.** Works with axum, actix-web, tonic, or plain functions. You decide how permissions are read and what a denied call returns.
- **No runtime dependencies**, `#![no_std]`, `#![forbid(unsafe_code)]`.
- **Composable requirements:** `any(...)` and `all(...)` can be nested.
- **Clear compile errors** that point at the argument or option that is wrong.

## Installation

```sh
cargo add permission_proc
```

## Usage

Implement `Permissions` for the type that carries the caller's identity:

```rust
use permission_proc::{permission, Permissions, Requirement};

struct Claims {
    permissions: Vec<String>,
}

impl Permissions for Claims {
    type Rejection = MyError;

    fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    fn permission_denied(&self, requirement: &Requirement) -> MyError {
        MyError::Forbidden(format!("missing permission: {requirement}"))
    }
}
```

Then guard your functions:

```rust
#[permission("posts:read")]
fn read(claims: &Claims) -> Result<Post, MyError> { /* ... */ }

#[permission(any("posts:delete", "posts:admin"))]
fn delete(claims: &Claims) -> Result<(), MyError> { /* ... */ }

#[permission(all("posts:write", any("team:editor", "team:owner")))]
fn publish(claims: &Claims) -> Result<(), MyError> { /* ... */ }
```

The check runs before the function body. On failure the function returns
`permission_denied(..)` converted with `Into`, wrapped in `Err(..)` when the
return type is a `Result`.

### axum

`Extension<Claims>` dereferences to `Claims`, so no glue code is needed:

```rust
impl Permissions for Claims {
    type Rejection = axum::response::Response;

    fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    fn permission_denied(&self, requirement: &Requirement) -> Response {
        (StatusCode::FORBIDDEN, format!("missing permission: {requirement}")).into_response()
    }
}

#[permission("posts:read")]
async fn list_posts(Extension(claims): Extension<Claims>) -> Response {
    // ...
}
```

See [`examples/axum.rs`](permission_proc/examples/axum.rs) for a runnable server.

## Options

| Syntax | Meaning |
|---|---|
| `#[permission("a")]` | Requires `a`. |
| `#[permission(any("a", "b"))]` | Requires at least one of them. |
| `#[permission(all("a", "b"))]` | Requires all of them. |
| `#[permission("a", claims = user)]` | Reads permissions from the binding `user`. |
| `#[permission("a", result = true)]` | Returns `Err(..)` on denial. Use it when the return type is an alias such as `ApiResult<T>`. |
| `#[permission("a", result = false)]` | Returns `rejection.into()` even though the return type looks like a `Result`. |
| `#[permission("a", crate = my::reexport)]` | Path to `permission_proc` when it is re-exported. |

### Which argument holds the claims?

1. The binding named by `claims = name`.
2. Otherwise, the argument marked with `#[claims]`:
   ```rust
   #[permission("a")]
   fn handler(#[claims] user: User, other: Config) -> Result<(), MyError> { /* ... */ }
   ```
3. Otherwise, the single argument whose type mentions a type ending in
   `Claims`, such as `Claims`, `JwtClaims`, `&Claims` or `Extension<Claims>`.

The argument can be a plain binding (`claims: Claims`) or a single-field tuple
struct pattern (`Extension(claims): Extension<Claims>`).

### Custom matching

`has_permission` is the place for wildcards, role hierarchies, and similar
rules. To evaluate a whole requirement at once, for example with a single
database query, override `Permissions::satisfies` as well.

```rust
impl Permissions for Claims {
    // ...
    fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| {
            p == permission
                || p.strip_suffix(":*").is_some_and(|prefix| permission.starts_with(prefix))
        })
    }
}
```

## Limitations

- Functions returning `impl Trait` cannot infer the `Into` conversion. Return
  a concrete type, or set `Rejection` to that type.
- The requirement is checked once, before the body runs. Ownership-based rules
  such as "may edit their own posts" still belong in the function body.

## Minimum supported Rust version

Rust 1.80, the same as axum 0.8.x.

## License

[MIT](LICENSE)
