#[derive(Debug,Clone)]
pub struct Config {
    pub db_url: String,
    pub jwt_secret: String,
    pub jwt_maxage: i64,
    pub port: i16
}

impl Config {
    pub fn init () -> Config {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET is required");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE is required");
        
        Config {
            db_url,
            jwt_secret,
            jwt_maxage: jwt_maxage.parse::<i64>().unwrap(),
            port:8000
        }

    }
}