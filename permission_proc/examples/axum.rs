//! An admin API guarded with `#[permission]`, laid out like a typical axum
//! service: JWT claims inserted by an auth middleware, a JSON response
//! envelope, and handlers grouped on an API struct.
//!
//! Run with `cargo run --example axum`, then:
//!
//! ```sh
//! # 401: no token
//! curl -i localhost:3000/forms
//!
//! # 200: the viewer token has `forms:read`
//! curl -i -H 'Authorization: Bearer viewer-token' localhost:3000/forms
//!
//! # 403: the viewer token lacks `forms:update`
//! curl -i -X PUT -H 'Authorization: Bearer viewer-token' \
//!      -H 'Content-Type: application/json' -d '{"status":"archived"}' \
//!      localhost:3000/forms/contact/status
//!
//! # 200: the admin token has every permission
//! curl -i -X PUT -H 'Authorization: Bearer admin-token' \
//!      -H 'Content-Type: application/json' -d '{"status":"archived"}' \
//!      localhost:3000/forms/contact/status
//! ```
//!
//! The modules mirror the crates of a larger workspace. `Permissions` is
//! implemented next to `Claims` because Rust's orphan rule requires the impl
//! to live in the crate that defines either the trait or the type.

use std::sync::Arc;

use api::AdminFormApi;
use state::AppState;

/// Shared types, e.g. a `types` crate.
mod types {
    pub mod jwt {
        use axum::{http::StatusCode, response::Response};
        use permission_proc::{Permissions, Requirement};
        use serde::{Deserialize, Serialize};

        use crate::response::error_response;

        #[derive(Debug, Serialize, Deserialize, Clone)]
        pub struct Claims {
            pub sub: String,
            pub role: String,
            pub permissions: Vec<String>,
            pub exp: i64,
            pub iat: i64,
            pub jti: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub sid: Option<i32>,
        }

        impl Permissions for Claims {
            type Rejection = Response;

            fn has_permission(&self, permission: &str) -> bool {
                self.permissions.iter().any(|p| p == permission)
            }

            fn permission_denied(&self, requirement: &Requirement) -> Response {
                error_response(
                    StatusCode::FORBIDDEN,
                    "invalid_data_error",
                    "Forbidden",
                    &format!("Missing permission: {requirement}"),
                )
            }
        }
    }
}

/// The JSON envelope every endpoint returns, e.g. a `core` crate.
mod response {
    use axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
        Json,
    };
    use serde::Serialize;
    use serde_json::json;

    pub fn error_response(
        status: StatusCode,
        error_type: &str,
        code: impl Serialize,
        message: &str,
    ) -> Response {
        (
            status,
            Json(json!({
                "status": "error",
                "error": { "error_type": error_type, "code": code, "message": message },
                "results": null,
            })),
        )
            .into_response()
    }

    pub enum ApiResult<R: Serialize> {
        Ok(R),
        NotFound,
    }

    impl<R: Serialize> IntoResponse for ApiResult<R> {
        fn into_response(self) -> Response {
            match self {
                ApiResult::Ok(results) => Json(json!({
                    "status": "success",
                    "error": null,
                    "results": results,
                }))
                .into_response(),
                ApiResult::NotFound => error_response(
                    StatusCode::NOT_FOUND,
                    "invalid_data_error",
                    "NotFound",
                    "The requested resource was not found.",
                ),
            }
        }
    }
}

/// Application state. A real service holds database pools here.
mod state {
    use std::{collections::HashMap, sync::Mutex};

    use serde::Serialize;

    use crate::types::jwt::Claims;

    #[derive(Clone, Serialize)]
    pub struct Form {
        pub id: String,
        pub status: String,
    }

    pub struct AppState {
        /// Stands in for JWT validation: token -> decoded claims.
        pub tokens: HashMap<&'static str, Claims>,
        pub forms: Mutex<Vec<Form>>,
    }

    impl AppState {
        pub fn demo() -> Self {
            let claims = |sub: &str, role: &str, permissions: &[&str]| Claims {
                sub: sub.into(),
                role: role.into(),
                permissions: permissions.iter().map(|p| p.to_string()).collect(),
                exp: i64::MAX,
                iat: 0,
                jti: format!("{sub}-jti"),
                sid: None,
            };
            AppState {
                tokens: HashMap::from([
                    (
                        "admin-token",
                        claims(
                            "1",
                            "admin",
                            &["forms:read", "forms:update", "forms:delete"],
                        ),
                    ),
                    ("viewer-token", claims("2", "viewer", &["forms:read"])),
                ]),
                forms: Mutex::new(vec![
                    Form {
                        id: "contact".into(),
                        status: "published".into(),
                    },
                    Form {
                        id: "survey".into(),
                        status: "draft".into(),
                    },
                ]),
            }
        }
    }
}

/// Authentication: turns the bearer token into `Extension<Claims>`.
mod middleware {
    use std::sync::Arc;

    use axum::{
        extract::{Request, State},
        http::StatusCode,
        middleware::Next,
        response::Response,
    };

    use crate::{response::error_response, state::AppState};

    pub async fn auth_middleware(
        State(state): State<Arc<AppState>>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, Response> {
        let unauthenticated = |message| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "auth_error",
                "Unauthenticated",
                message,
            )
        };

        let token = request
            .headers()
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| unauthenticated("Missing authorization token"))?;
        let claims = state
            .tokens
            .get(token)
            .cloned()
            .ok_or_else(|| unauthenticated("Invalid authorization token"))?;

        request.extensions_mut().insert(claims);
        Ok(next.run(request).await)
    }
}

/// An admin API: routes, then handlers guarded with `#[permission]`.
mod api {
    use std::sync::Arc;

    use axum::{
        extract::{Path, State},
        response::{IntoResponse, Response},
        routing::{delete, get, put},
        Extension, Json, Router,
    };
    use permission_proc::permission;
    use serde::Deserialize;

    use crate::{
        middleware::auth_middleware, response::ApiResult, state::AppState, types::jwt::Claims,
    };

    pub struct AdminFormApi {
        app_state: Arc<AppState>,
    }

    #[derive(Deserialize)]
    pub struct UpdateFormStatusRequest {
        status: String,
    }

    impl AdminFormApi {
        pub fn new(app_state: Arc<AppState>) -> Self {
            Self { app_state }
        }

        pub fn into_router(self) -> Router {
            Router::new()
                .route("/forms", get(Self::list_forms))
                .route("/forms/{id}", delete(Self::delete_form))
                .route("/forms/{id}/status", put(Self::update_status))
                .route_layer(axum::middleware::from_fn_with_state(
                    self.app_state.clone(),
                    auth_middleware,
                ))
                .with_state(Arc::new(self))
        }

        #[permission("forms:read")]
        async fn list_forms(
            State(this): State<Arc<Self>>,
            Extension(_claims): Extension<Claims>,
        ) -> Response {
            let forms = this.app_state.forms.lock().unwrap().clone();
            ApiResult::Ok(forms).into_response()
        }

        #[permission("forms:update")]
        async fn update_status(
            State(this): State<Arc<Self>>,
            Extension(_claims): Extension<Claims>,
            Path(id): Path<String>,
            Json(request): Json<UpdateFormStatusRequest>,
        ) -> Response {
            let mut forms = this.app_state.forms.lock().unwrap();
            match forms.iter_mut().find(|form| form.id == id) {
                Some(form) => {
                    form.status = request.status;
                    ApiResult::Ok("Successfully updated form status").into_response()
                }
                None => ApiResult::<()>::NotFound.into_response(),
            }
        }

        // `any(...)`: either permission is enough.
        #[permission(any("forms:delete", "forms:admin"))]
        async fn delete_form(
            State(this): State<Arc<Self>>,
            Extension(claims): Extension<Claims>,
            Path(id): Path<String>,
        ) -> Response {
            let mut forms = this.app_state.forms.lock().unwrap();
            let before = forms.len();
            forms.retain(|form| form.id != id);
            if forms.len() == before {
                return ApiResult::<()>::NotFound.into_response();
            }
            ApiResult::Ok(format!("Form deleted by account {}", claims.sub)).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    let app = AdminFormApi::new(Arc::new(AppState::demo())).into_router();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
