use chrono::{DateTime, Utc};
use core::str;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::models::{User, UserRole};

fn validate_length_with_custom_message(
    value: &str,
    field_name: &str,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        let mut error = ValidationError::new("required");
        error.message = Some(format!("{} is required", field_name).into());
        return Err(error);
    }

    if value.len() < 6 {
        let mut error = ValidationError::new("min_length");
        error.message = Some(format!("{} must be at least 6 characters long", field_name).into());
        return Err(error);
    }

    Ok(())
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    validate_length_with_custom_message(password, "Password")
}

fn validate_new_password(password: &str) -> Result<(), ValidationError> {
    validate_length_with_custom_message(password, "New password")
}

fn validate_confirm_new_password(password: &str) -> Result<(), ValidationError> {
    validate_length_with_custom_message(password, "Confirm new password")
}

fn validate_old_password(password: &str) -> Result<(), ValidationError> {
    validate_length_with_custom_message(password, "Old password")
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RegisterUserDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(custom(function = validate_password))]
    pub password: String,

    #[validate(
        length(min = 1, message = "Confirm Password is required"),
        must_match(other = "password", message = "passwords do not match")
    )]
    #[serde(rename = "passwordConfirm")]
    pub password_confirm: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUserDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(custom(function = validate_password))]
    pub password: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUserDto {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            id: user.id.to_string(),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            verified: user.verified,
            role: user.role.to_str().to_string(),
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUserDto> {
        user.iter().map(FilterUserDto::filter_user).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUserDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponseDto {
    pub status: String,
    pub users: Vec<FilterUserDto>,
    pub results: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginResponseDto {
    pub status: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct NameUpdateDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RoleUpdateDto {
    #[validate(custom(function = validate_user_role))]
    pub role: UserRole,
}

fn validate_user_role(role: &UserRole) -> Result<(), validator::ValidationError> {
    match role {
        UserRole::Admin | UserRole::User => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_role")),
    }
}

#[derive(Debug, Validate, Default, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdateDto {
    #[validate(custom(function = validate_new_password))]
    pub new_password: String,
    #[validate(custom(function = validate_confirm_new_password))]
    #[validate(must_match(other = "new_password", message = "new passwords do not match"))]
    pub new_password_confirm: String,

    #[validate(custom(function = validate_old_password))]
    pub old_password: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct VerifyEmailQueryDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct ForgotPasswordRequestDto {
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct ResetPasswordRequestDto {
    #[validate(length(min = 1, message = "Token is required."))]
    pub token: String,
    #[validate(custom(function = validate_new_password))]
    pub new_password: String,

    #[validate(custom(function = validate_confirm_new_password))]
    #[validate(must_match(other = "new_password", message = "new passwords do not match"))]
    pub new_password_confirm: String,
}

#[derive(Serialize, Deserialize)]
pub struct RequestDeleteUserDto {
    pub id: Option<String>,
    pub email: Option<String>,
    pub verification_token: Option<String>,
}

impl RequestDeleteUserDto {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_some() || self.email.is_some() || self.verification_token.is_some() {
            Ok(())
        } else {
            Err("At least one of `id`, `email`, or `verification_token` must be provided.".to_string())
        }
    }
}