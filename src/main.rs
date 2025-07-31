use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use reqwest;
use serde_json;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use actix_web::middleware::Logger;
use actix_cors::Cors;
use std::fs;
use std::env;
use std::path::Path;
use std::sync::Arc;
use dotenv::dotenv;
use std::io::ErrorKind;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Clone, Debug)]
struct AppState {
    rsa_modulus: String,
    rsa_exponent: String,
    kid: String
}

async fn verify_jwks_file_exists(jwks_path: &str, jwks_client_id: &str) -> Result<(), String> {
    if Path::new(jwks_path).exists() {
        return Ok(());
    }

    let client = reqwest::Client::new();
    let jwks = client
        .get(&format!("https://api.workos.com/sso/jwks/{}", jwks_client_id))
        .send()
        .await
        .map_err(|e| format!("Failed to download JWKS: {}", e))?
        .text()
        .await
        .map_err(|e| format!("Failed to read JWKS response: {}", e))?;

    fs::write(jwks_path, &jwks)
        .map_err(|e| format!("Failed to write JWKS file: {}", e))?;

    Ok(())
}

fn get_app_state(jwks_path: &str) -> Result<AppState, String> {
    let jwks_content = fs::read_to_string(jwks_path)
        .map_err(|e| format!("Failed to read JWKS file: {}", e))?;

    let jwks_json: serde_json::Value = serde_json::from_str(&jwks_content)
        .map_err(|e| format!("Failed to parse JWKS JSON: {}", e))?;

    let key = jwks_json
        .get("keys")
        .and_then(|keys| keys.get(0))
        .ok_or("No keys found in JWKS".to_string())?;

    Ok(AppState {
        rsa_modulus: key
            .get("n")
            .and_then(|v| v.as_str())
            .ok_or("Missing RSA modulus in JWKS".to_string())?
            .to_string(),
        rsa_exponent: key
            .get("e")
            .and_then(|v| v.as_str())
            .ok_or("Missing RSA exponent in JWKS".to_string())?
            .to_string(),
        kid: key
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or("Missing key ID in JWKS".to_string())?
            .to_string(),
    })
}

async fn validate_token(
    req: actix_web::HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    let auth_header = match req.headers().get("Authorization") {
        Some(header) => match header.to_str() {
            Ok(header) => header,
            Err(_) => return HttpResponse::BadRequest().json("Invalid Authorization header"),
        },
        None => return HttpResponse::BadRequest().json("Missing Authorization header"),
    };

    let token = match auth_header.strip_prefix("Bearer ") {
        Some(token) => token,
        None => return HttpResponse::BadRequest().json("Invalid or missing Bearer token"),
    };

    if token.is_empty() {
        return HttpResponse::BadRequest().json("Empty Bearer token");
    }

    let header = match jsonwebtoken::decode_header(token) {
        Ok(header) => header,
        Err(e) => return HttpResponse::BadRequest().json(format!("Invalid token header: {}", e)),
    };

    if header.kid.as_ref().map_or(true, |kid| kid != &state.kid) {
        return HttpResponse::Unauthorized().json("Token key ID does not match");
    }

    let decoding_key = match DecodingKey::from_rsa_components(&state.rsa_modulus, &state.rsa_exponent) {
        Ok(key) => key,
        Err(e) => return HttpResponse::InternalServerError().json(format!("Failed to create decoding key: {}", e)),
    };

    let validation = Validation::new(Algorithm::RS256);

    match decode::<Claims>(token, &decoding_key, &validation) {
        Ok(token_data) => HttpResponse::Ok().json(token_data.claims),
        Err(e) => HttpResponse::Unauthorized().json(format!("Invalid token: {}", e)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let jwks_client_id = env::var("JWKS_CLIENT_ID")
        .map_err(|_| std::io::Error::new(ErrorKind::Other, "JWKS_CLIENT_ID environment variable not set"))?;

    let jwks_path = &format!("{}-jwks.json", jwks_client_id);

    if let Err(e) = verify_jwks_file_exists(jwks_path, &jwks_client_id).await {
        eprintln!("Failed to verify JWKS file: {}", e);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
    }

    let app_state = match get_app_state(jwks_path) {
        Ok(state) => Arc::new(state),
        Err(e) => {
            eprintln!("Failed to initialize app state: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
    };

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .route("/verify", web::get().to(validate_token))
            .wrap(cors)
            .wrap(Logger::default())
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}
