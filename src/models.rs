use chrono::prelude::*;
use serde::{Serialize,Deserialize};

#[derive(Serialize,Deserialize,Debug,Clone,Copy, sqlx::Type, PartialEq)]
#[sqlx(type_name="user_role", rename_all="lowercase")]

pub enum UserRole{
    Admin,
    User
}

impl UserRole {
    pub fn to_str(&self)->&str{
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user"
        }
    }
}

#[derive(Debug,Deserialize,Serialize, sqlx::FromRow, sqlx::Type, Clone)]

pub struct  User{
    pub id: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: UserRole,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub token_expiry: Option<DateTime<Utc>>,
    #[serde(rename="createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename="updatedAt")]
    pub updated_at: DateTime<Utc>
}