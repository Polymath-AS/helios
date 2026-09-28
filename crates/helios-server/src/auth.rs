//! HS256 API tokens and the admin bearer secret. Revocation is checked
//! against the in-memory token table, so it takes effect immediately.

use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::state::Locked;
use crate::error::ApiError;
use crate::state::{AppState, CacheInfo};

pub const ISSUER: &str = "helios-cache";
pub const AUDIENCE: &str = "helios-cache";
const HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_CLOCK_SKEW: i64 = 60;
pub const MAX_CACHES_PER_TOKEN: usize = 50;
pub const MAX_PERMS_PER_TOKEN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Perm {
    Pull,
    Push,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub jti: String,
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub caches: Vec<String>,
    pub perms: Vec<Perm>,
    pub iat: i64,
    pub exp: i64,
}

impl Claims {
    pub fn allows(&self, cache: &str, perm: Perm) -> bool {
        self.perms.contains(&perm) && self.caches.iter().any(|c| c == "*" || c == cache)
    }
}

pub enum Identity {
    Token(Claims),
    Admin,
}

impl Identity {
    pub fn actor(&self) -> &str {
        match self {
            Identity::Token(c) => &c.jti,
            Identity::Admin => "admin",
        }
    }
}

pub fn sign(claims: &Claims, secret: &[u8]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialise"));
    let input = format!("{HEADER_B64}.{payload}");
    let sig = URL_SAFE_NO_PAD.encode(helios_core::hmac_sha256(secret, input.as_bytes()));
    format!("{input}.{sig}")
}

fn verify(token: &str, secret: &[u8], now: i64) -> Option<Claims> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let (signed, sig_b64) = token.rsplit_once('.')?;
    let (header, payload_b64) = signed.split_once('.')?;
    if header != HEADER_B64 || payload_b64.contains('.') {
        return None;
    }
    let sig = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    if !helios_core::ct_eq(&helios_core::hmac_sha256(secret, signed.as_bytes()), &sig) {
        return None;
    }

    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).ok()?).ok()?;
    let valid = !claims.jti.is_empty()
        && !claims.sub.is_empty()
        && claims.iss == ISSUER
        && claims.aud == AUDIENCE
        && claims.iat <= now + MAX_CLOCK_SKEW
        && claims.exp > claims.iat
        && claims.exp > now - MAX_CLOCK_SKEW
        && (1..=MAX_CACHES_PER_TOKEN).contains(&claims.caches.len())
        && (1..=MAX_PERMS_PER_TOKEN).contains(&claims.perms.len())
        && claims.caches.iter().all(|c| !c.is_empty());
    valid.then_some(claims)
}

/// Bearer token, or the password of HTTP Basic auth (what Nix sends from netrc).
fn credential(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    let rest = rest.trim();
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.to_owned());
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
        let (_, password) = decoded.split_once(':')?;
        return Some(password.to_owned());
    }
    None
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Hash first so the comparison does not leak the secret's length.
    helios_core::ct_eq(&helios_core::sha256(a), &helios_core::sha256(b))
}

impl AppState {
    fn token_claims(&self, headers: &HeaderMap) -> Result<Claims, ApiError> {
        let secret = self.cfg.jwt_secret.as_deref().ok_or_else(ApiError::forbidden)?;
        let token = credential(headers).ok_or_else(ApiError::unauthorized)?;
        let now = crate::db::now();
        let claims = verify(&token, secret, now).ok_or_else(ApiError::unauthorized)?;
        match self.tokens.rd().get(claims.jti.as_str()) {
            Some(t) if !t.revoked && t.expires_at > now => Ok(claims),
            _ => Err(ApiError::unauthorized()),
        }
    }

    /// Requires a token granting `perm` on `cache`.
    pub fn authorize(&self, headers: &HeaderMap, cache: &str, perm: Perm) -> Result<Identity, ApiError> {
        let claims = self.token_claims(headers)?;
        if !claims.allows(cache, perm) {
            return Err(ApiError::forbidden());
        }
        Ok(Identity::Token(claims))
    }

    /// Public caches are readable by anyone; private ones need `pull`.
    pub fn authorize_read(&self, headers: &HeaderMap, name: &str, cache: CacheInfo) -> Result<(), ApiError> {
        if cache.public {
            return Ok(());
        }
        self.authorize(headers, name, Perm::Pull).map(|_| ())
    }

    pub fn authorize_admin(&self, headers: &HeaderMap) -> Result<Identity, ApiError> {
        let secret = self.cfg.admin_secret.as_deref().ok_or_else(ApiError::forbidden)?;
        let given = credential(headers).ok_or_else(ApiError::unauthorized)?;
        if !constant_time_eq(given.as_bytes(), secret) {
            return Err(ApiError::forbidden());
        }
        Ok(Identity::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(now: i64) -> Claims {
        Claims {
            jti: "id".into(),
            sub: "ci".into(),
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            caches: vec!["main".into()],
            perms: vec![Perm::Push],
            iat: now,
            exp: now + 3600,
        }
    }

    #[test]
    fn round_trip_and_tamper() {
        let now = 1_700_000_000;
        let token = sign(&claims(now), b"0123456789abcdef");
        assert!(verify(&token, b"0123456789abcdef", now).is_some());
        assert!(verify(&token, b"0123456789abcdeX", now).is_none());
        assert!(verify(&token, b"0123456789abcdef", now + 7200).is_none());
        let mut tampered = token.clone();
        tampered.insert(token.find('.').unwrap() + 3, 'x');
        assert!(verify(&tampered, b"0123456789abcdef", now).is_none());
    }

    #[test]
    fn header_constant_matches() {
        assert_eq!(URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#), HEADER_B64);
    }

    #[test]
    fn scope_checks() {
        let c = claims(0);
        assert!(c.allows("main", Perm::Push));
        assert!(!c.allows("main", Perm::Pull));
        assert!(!c.allows("other", Perm::Push));
    }
}
