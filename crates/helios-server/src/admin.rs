//! Admin API: caches and API tokens. Authenticated with the admin secret.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::state::Locked;
use crate::audit::Audit;
use crate::auth::{self, AUDIENCE, Claims, ISSUER, MAX_CACHES_PER_TOKEN, MAX_PERMS_PER_TOKEN, Perm};
use crate::error::{ApiError, ApiResult};
use crate::state::{Shared, TokenState};

const MAX_TOKEN_LIFETIME_DAYS: i64 = 365;
const DEFAULT_TOKEN_LIFETIME_DAYS: i64 = 90;
const MAX_SUBJECT_LEN: usize = 256;
const MAX_REASON_LEN: usize = 512;

fn valid_cache_name(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=64).contains(&b.len())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

#[derive(Deserialize)]
pub struct CreateCacheReq {
    name: String,
    #[serde(default = "default_true")]
    public: bool,
}

fn default_true() -> bool {
    true
}

pub async fn create_cache(
    State(st): State<Shared>,
    audit: Audit,
    headers: HeaderMap,
    Json(req): Json<CreateCacheReq>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let who = st.authorize_admin(&headers)?;
    if !valid_cache_name(&req.name) {
        return Err(ApiError::bad_request("cache name must be 1-64 lowercase alphanumerics or hyphens, no leading/trailing hyphen"));
    }
    let st2 = st.clone();
    let name = req.name.clone();
    let created = tokio::task::spawn_blocking(move || st2.insert_cache(&name, req.public)).await??;
    let status = if created.is_some() { StatusCode::CREATED } else { StatusCode::CONFLICT };
    audit.log(&st, &who, "cache.create", Some(&req.name), status, json!({ "public": req.public }));
    match created {
        Some(info) => Ok((status, Json(json!({ "name": req.name, "public": info.public })))),
        None => Err(ApiError::new(status, "cache already exists")),
    }
}

pub async fn list_caches(State(st): State<Shared>, headers: HeaderMap) -> ApiResult<Json<serde_json::Value>> {
    st.authorize_admin(&headers)?;
    let mut caches: Vec<_> = st.caches.rd().iter().map(|(name, c)| json!({ "name": name, "public": c.public })).collect();
    caches.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(json!({ "caches": caches })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenReq {
    subject: String,
    caches: Vec<String>,
    perms: Vec<Perm>,
    expires_in_days: Option<i64>,
}

pub async fn create_token(
    State(st): State<Shared>,
    audit: Audit,
    headers: HeaderMap,
    Json(req): Json<CreateTokenReq>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let who = st.authorize_admin(&headers)?;
    let secret = st.cfg.jwt_secret.clone().ok_or_else(|| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "token signing is not configured"))?;
    if req.subject.is_empty() || req.subject.len() > MAX_SUBJECT_LEN {
        return Err(ApiError::bad_request("subject must be 1-256 characters"));
    }
    let mut caches = req.caches;
    caches.sort();
    caches.dedup();
    if caches.is_empty() || caches.len() > MAX_CACHES_PER_TOKEN || caches.iter().any(|c| c != "*" && !valid_cache_name(c)) {
        return Err(ApiError::bad_request(format!("caches must be 1-{MAX_CACHES_PER_TOKEN} cache names or \"*\"")));
    }
    let mut perms = req.perms;
    perms.sort();
    perms.dedup();
    if perms.is_empty() || perms.len() > MAX_PERMS_PER_TOKEN {
        return Err(ApiError::bad_request("perms must be a non-empty list of \"pull\" and/or \"push\""));
    }
    let days = req.expires_in_days.unwrap_or(DEFAULT_TOKEN_LIFETIME_DAYS);
    if !(1..=MAX_TOKEN_LIFETIME_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!("expiresInDays must be between 1 and {MAX_TOKEN_LIFETIME_DAYS}")));
    }

    let now = crate::db::now();
    let claims = Claims {
        jti: helios_core::uuid_v4(),
        sub: req.subject,
        iss: ISSUER.into(),
        aud: AUDIENCE.into(),
        caches,
        perms,
        iat: now,
        exp: now + days * 86400,
    };
    let token = auth::sign(&claims, &secret);
    let db = st.db.clone();
    let row = claims.clone();
    tokio::task::spawn_blocking(move || {
        db.write(|conn| {
            conn.execute(
                "INSERT INTO tokens (jti, subject, caches, perms, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    row.jti,
                    row.sub,
                    serde_json::to_string(&row.caches).unwrap_or_default(),
                    serde_json::to_string(&row.perms).unwrap_or_default(),
                    row.iat,
                    row.exp
                ],
            )
        })
    })
    .await??;
    st.tokens.wr().insert(claims.jti.as_str().into(), TokenState { expires_at: claims.exp, revoked: false });
    audit.log(&st, &who, "token.create", None, StatusCode::CREATED, json!({ "jti": claims.jti, "subject": claims.sub }));
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "token": token,
            "jti": claims.jti,
            "subject": claims.sub,
            "caches": claims.caches,
            "perms": claims.perms,
            "expiresAt": claims.exp,
        })),
    ))
}

pub async fn list_tokens(State(st): State<Shared>, headers: HeaderMap) -> ApiResult<Json<serde_json::Value>> {
    st.authorize_admin(&headers)?;
    let db = st.db.clone();
    let tokens = tokio::task::spawn_blocking(move || {
        db.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT jti, subject, caches, perms, created_at, expires_at, revoked_at, revoked_by, revocation_reason
                 FROM tokens ORDER BY created_at",
            )?;
            let rows = stmt.query_map([], |r| {
                let caches: String = r.get(2)?;
                let perms: String = r.get(3)?;
                Ok(json!({
                    "jti": r.get::<_, String>(0)?,
                    "subject": r.get::<_, String>(1)?,
                    "caches": serde_json::from_str::<serde_json::Value>(&caches).unwrap_or_default(),
                    "perms": serde_json::from_str::<serde_json::Value>(&perms).unwrap_or_default(),
                    "createdAt": r.get::<_, i64>(4)?,
                    "expiresAt": r.get::<_, i64>(5)?,
                    "revokedAt": r.get::<_, Option<i64>>(6)?,
                    "revokedBy": r.get::<_, Option<String>>(7)?,
                    "revocationReason": r.get::<_, Option<String>>(8)?,
                }))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
    })
    .await??;
    Ok(Json(json!({ "tokens": tokens })))
}

#[derive(Deserialize)]
pub struct RevokeReq {
    reason: String,
}

pub async fn revoke_token(
    State(st): State<Shared>,
    Path(jti): Path<String>,
    audit: Audit,
    headers: HeaderMap,
    Json(req): Json<RevokeReq>,
) -> ApiResult<Json<serde_json::Value>> {
    let who = st.authorize_admin(&headers)?;
    if req.reason.is_empty() || req.reason.len() > MAX_REASON_LEN {
        return Err(ApiError::bad_request("reason must be 1-512 characters"));
    }
    let db = st.db.clone();
    let id = jti.clone();
    let changed = tokio::task::spawn_blocking(move || {
        db.write(|conn| {
            conn.execute(
                "UPDATE tokens SET revoked_at = ?2, revoked_by = 'admin', revocation_reason = ?3 WHERE jti = ?1 AND revoked_at IS NULL",
                params![id, crate::db::now(), req.reason],
            )
        })
    })
    .await??;
    if changed == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "token not found or already revoked"));
    }
    if let Some(t) = st.tokens.wr().get_mut(jti.as_str()) {
        t.revoked = true;
    }
    audit.log(&st, &who, "token.revoke", None, StatusCode::OK, json!({ "jti": jti }));
    Ok(Json(json!({ "revoked": true, "jti": jti })))
}
