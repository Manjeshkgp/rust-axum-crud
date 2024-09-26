use crate::{
    db::UserExt,
    dtos::{
        FilterUserDto, NameUpdateDto, RequestDeleteUserDto, RequestQueryDto, Response,
        RoleUpdateDto, UserData, UserListResponseDto, UserPasswordUpdateDto, UserResponseDto,
    },
    error::{ErrorMessage, HttpError},
    middleware::{role_check, JWTAuthMiddleware},
    models::UserRole,
    utils::password,
    AppState,
};
use axum::{
    extract::Query,
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, put},
    Extension, Json, Router,
};
use std::sync::Arc;
use validator::Validate;

pub fn users_handler() -> Router {
    Router::new()
        .route(
            "/me",
            get(get_me).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin, UserRole::User])
            })),
        )
        .route(
            "/users",
            get(get_users).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route(
            "/delete",
            delete(delete_user).layer(middleware::from_fn(|state, req, next| {
                role_check(state, req, next, vec![UserRole::Admin])
            })),
        )
        .route("/name", put(update_user_name))
        .route("/role", put(update_user_role))
        .route("/password", put(update_user_password))
}

pub async fn get_me(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    let filtered_user = FilterUserDto::filter_user(&user.user);
    let response_data = UserResponseDto {
        status: "sucess".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };
    Ok(Json(response_data))
}

pub async fn get_users(
    Query(query_params): Query<RequestQueryDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let _ = query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()));
    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(12);
    let users = app_state
        .db_client
        .get_users(page as u32, limit)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let user_count = app_state
        .db_client
        .get_user_count()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let response = UserListResponseDto {
        status: "success".to_string(),
        users: FilterUserDto::filter_users(&users),
        results: user_count,
    };
    Ok(Json(response))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<NameUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    let user = &user.user;
    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();
    let result = app_state
        .db_client
        .update_user_name(user_id, &body.name)
        .await
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    let filtered_user = FilterUserDto::filter_user(&result);
    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };
    Ok(Json(response))
}

pub async fn update_user_role(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<RoleUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    let user = &user.user;
    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();
    let result = app_state
        .db_client
        .update_user_role(user_id, body.role)
        .await
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    let filtered_user = FilterUserDto::filter_user(&result);
    let response = UserResponseDto {
        data: UserData {
            user: filtered_user,
        },
        status: "success".to_string(),
    };
    Ok(Json(response))
}

pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<UserPasswordUpdateDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    let user = &user.user;
    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();
    let result = app_state
        .db_client
        .get_user(Some(user_id.clone()), None, None, None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let user = result.ok_or(HttpError::unauthorized(
        ErrorMessage::InvalidToken.to_string(),
    ))?;

    let password_matched = password::compare(&body.old_password, &user.password)
        .map_err(|e| HttpError::bad_request(e.to_string()))?;
    if !password_matched {
        return Err(HttpError::bad_request(
            "Old password is incorrect".to_string(),
        ));
    }

    let hash_password =
        password::hash(&body.new_password).map_err(|e| HttpError::server_error(e.to_string()))?;

    app_state
        .db_client
        .update_user_password(user_id, hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    let response = Response {
        status: "success",
        message: "Password updated successfully".to_string(),
    };
    Ok(Json(response))
}

pub async fn delete_user(
    Extension(app_state): Extension<Arc<AppState>>,
    Query(query_params): Query<RequestDeleteUserDto>,
) -> Result<impl IntoResponse, HttpError> {
    let _ = query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user_id = query_params
        .id
        .as_deref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok());
    let user_email = query_params.email.as_deref();
    let verification_token = query_params.verification_token.as_deref();

    // Execute the DELETE query
    let result = app_state
        .db_client
        .delete_user(user_id, user_email, verification_token)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    // Check the number of rows affected
    if result > 0 {
        let response = Response {
            status: "success",
            message: "User deleted successfully".to_string(),
        };
        Ok(Json(response))
    } else {
        Err(HttpError::new("User not found", StatusCode::NOT_FOUND))
    }
}
