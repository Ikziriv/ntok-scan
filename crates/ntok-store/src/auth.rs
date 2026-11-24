//! Per-user accounts for the web/API surfaces — argon2id password
//! hashes, opaque session cookies, and revocable API tokens, all in
//! the same `ntok.db` so backups and restores carry credentials too.
//!
//! Tokens are stored as SHA-256 digests; the raw value is returned to
//! the caller exactly once (create time).

use crate::{Error, Result};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// A registered account.
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    /// Login alias and monitoring label — `None` for accounts created
    /// before the column existed (e.g. the seeded `admin`).
    pub email: Option<String>,
    /// Display name for the account — `name` stays the login key.
    pub full_name: Option<String>,
}

/// A created API token — the secret itself is never stored, so the
/// list view shows metadata only.
#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub created_unix: u64,
    pub last_used: Option<u64>,
}

/// One live session for the "active sessions" list.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token: String,
    pub created_unix: u64,
    pub expires_unix: u64,
}

/// One row of the auth audit log — login attempts, password and TOTP
/// changes, registrations.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub name: String,
    pub ip: String,
    pub event: String,
    pub unix_ts: u64,
}

pub(super) const AUTH_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email        TEXT,
    full_name    TEXT,
    pass_hash    TEXT NOT NULL,
    totp_secret  TEXT,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    lock_until   INTEGER,
    created_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_unix INTEGER NOT NULL,
    expires_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_unix INTEGER NOT NULL,
    last_used    INTEGER
);
CREATE TABLE IF NOT EXISTS auth_events (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    ip       TEXT NOT NULL,
    event    TEXT NOT NULL,
    unix_ts  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_events_name ON auth_events(name, unix_ts);
CREATE INDEX IF NOT EXISTS auth_events_ts ON auth_events(unix_ts);
CREATE INDEX IF NOT EXISTS sessions_exp ON sessions(expires_unix);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(user_id);
";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `ntok_` prefix so leaked tokens are greppable, then 32 random bytes
/// hex-encoded — 128 bits, unguessable, URL/header safe.
fn random_token() -> String {
    let mut b = [0u8; 32];
    // RNG failure can't produce a weak token — it produces no token.
    getrandom::fill(&mut b).expect("system RNG unavailable");
    let mut s = String::with_capacity(4 + 64);
    s.push_str("ntok_");
    hex_into(&b, &mut s);
    s
}

/// Lowercase hex, one allocation — not one `format!` per byte.
fn hex_into(bytes: &[u8], out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
}

fn token_digest(token: &str) -> String {
    let d = Sha256::digest(token.as_bytes());
    let mut s = String::with_capacity(64);
    hex_into(&d, &mut s);
    s
}

/// `SELECT id, name, email, full_name` → `User` — the column order every
/// user lookup uses.
fn row_user(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        name: r.get(1)?,
        email: r.get(2)?,
        full_name: r.get(3)?,
    })
}

/// Login accepts the username or the email — the shared predicate for
/// `verify_user` and the lockout counters, glued into const queries so
/// no SQL string is rebuilt per call.
macro_rules! who_where {
    ($prefix:literal) => {
        concat!($prefix, "name = ? OR email = ? COLLATE NOCASE")
    };
}
const WHO_VERIFY: &str =
    who_where!("SELECT id, name, email, full_name, pass_hash FROM users WHERE ");
const WHO_LOCK: &str = who_where!("SELECT lock_until FROM users WHERE ");
const WHO_FAILS: &str = who_where!("SELECT id, fail_count, lock_until FROM users WHERE ");
const WHO_CLEAR: &str = who_where!("UPDATE users SET fail_count = 0, lock_until = NULL WHERE ");

/// Blank → `None`; otherwise trimmed. Email is a label, not a verified
/// contact (local-first, no SMTP) — so validation stays minimal.
fn clean_email(email: &str) -> Result<Option<String>> {
    let e = email.trim();
    if e.is_empty() {
        return Ok(None);
    }
    if e.len() > 254 || !e.contains('@') {
        return Err(Error::Query("invalid email address".into()));
    }
    Ok(Some(e.to_string()))
}

fn clean_full_name(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn hash_password(password: &str) -> Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| Error::Query(format!("password hash failed: {e}")))
}

fn check_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

/// New TOTP secret: 160 random bits base32-encoded (no padding) so it
/// drops straight into an otpauth:// URI or manual entry field.
pub fn new_totp_secret() -> String {
    let mut b = [0u8; 20];
    getrandom::fill(&mut b).expect("system RNG unavailable");
    data_encoding::BASE32_NOPAD.encode(&b)
}

/// RFC 6238 TOTP value for `secret_b32` at 30s `step` — 6 digits.
pub fn totp_code(secret_b32: &str, step: u64) -> Option<String> {
    let key = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .ok()?;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).ok()?;
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0xf) as usize;
    let code = (u32::from_be_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]]) & 0x7fff_ffff)
        % 1_000_000;
    Some(format!("{code:06}"))
}

/// Constant-time equality over equal-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Check a user-entered code, accepting the current step ±1 for clock
/// skew. Input must be exactly 6 digits (spaces stripped).
pub fn totp_check(secret_b32: &str, code: &str) -> bool {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = now() / 30;
    (-1..=1i64).any(|d| {
        step.checked_add_signed(d)
            .and_then(|s| totp_code(secret_b32, s))
            .is_some_and(|c| ct_eq(c.as_bytes(), code.as_bytes()))
    })
}

/// User/session/token operations — all take `&self` on [`Store`](crate::Store).
impl crate::Store {
    pub fn user_count(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM users", [], |r| r.get(0))?)
    }

    /// Register an account. Names are case-insensitive unique, as are
    /// emails when given; the password must be at least 8 chars (checked
    /// again at the edge). Empty `email`/`full_name` store `NULL`.
    pub fn create_user(
        &self,
        name: &str,
        email: &str,
        full_name: &str,
        password: &str,
    ) -> Result<User> {
        let name = name.trim();
        if name.is_empty() || name.contains('@') || password.len() < 8 || password.len() > 1024 {
            return Err(Error::Query(
                "name required (no '@'), password 8–1024 chars".into(),
            ));
        }
        let email = clean_email(email)?;
        let full_name = clean_full_name(full_name);
        let hash = hash_password(password)?;
        self.conn.execute(
            "INSERT INTO users (name, email, full_name, pass_hash, created_unix)
             VALUES (?,?,?,?,?)",
            rusqlite::params![name, email, full_name, hash, now() as i64],
        )?;
        Ok(User {
            id: self.conn.last_insert_rowid(),
            name: name.to_string(),
            email,
            full_name,
        })
    }

    /// Login check — `who` may be the username or the email; `None` on
    /// unknown account or wrong password, with constant-work argon2 check
    /// so timing does not leak account existence.
    pub fn verify_user(&self, who: &str, password: &str) -> Result<Option<User>> {
        static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
            hash_password("ntok-dummy-password-for-timing").expect("argon2 dummy hash")
        });
        if password.len() > 1024 {
            return Ok(None);
        }
        let who = who.trim();
        let row = self
            .conn
            .query_row(WHO_VERIFY, [who, who], |r| {
                Ok((row_user(r)?, r.get::<_, String>(4)?))
            })
            .optional()?;
        let hash = row.as_ref().map(|(_, h)| h.as_str()).unwrap_or(&DUMMY_HASH);
        let ok = check_password(password, hash);
        Ok(row.and_then(|(u, _)| ok.then_some(u)))
    }

    /// New session cookie value — random, sweeps expired sessions on creation.
    pub fn create_session(&self, user_id: i64, ttl_secs: u64) -> Result<String> {
        let token = random_token();
        let t = now();
        let exp = t.saturating_add(ttl_secs).min(i64::MAX as u64) as i64;
        self.conn
            .execute("DELETE FROM sessions WHERE expires_unix < ?", [t as i64])?;
        self.conn.execute(
            "INSERT INTO sessions (token, user_id, created_unix, expires_unix)
             VALUES (?,?,?,?)",
            rusqlite::params![token, user_id, t as i64, exp],
        )?;
        Ok(token)
    }

    /// Resolve a session cookie to a user (read-only on the hot path;
    /// expired sessions are filtered here and swept on `create_session`).
    pub fn user_for_session(&self, token: &str) -> Result<Option<User>> {
        let t = now() as i64;
        let mut st = self.conn.prepare_cached(
            "SELECT u.id, u.name, u.email, u.full_name FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token = ? AND s.expires_unix >= ?",
        )?;
        Ok(st
            .query_row(rusqlite::params![token, t], row_user)
            .optional()?)
    }

    pub fn drop_session(&self, token: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sessions WHERE token = ?", [token])?;
        Ok(())
    }

    /// Mint an API token for `user_id`. The returned string is the only
    /// time the secret exists — the DB keeps only its SHA-256.
    pub fn create_api_token(&self, user_id: i64, name: &str) -> Result<String> {
        let token = random_token();
        self.conn.execute(
            "INSERT INTO api_tokens (user_id, name, token_hash, created_unix)
             VALUES (?,?,?,?)",
            rusqlite::params![user_id, name.trim(), token_digest(&token), now() as i64],
        )?;
        Ok(token)
    }

    /// Resolve a `Bearer` token to a user and stamp `last_used` (throttled
    /// to once per 60s so hot API reads don't contend on the WAL write lock).
    pub fn user_for_api_token(&self, token: &str) -> Result<Option<User>> {
        let digest = token_digest(token);
        let row = {
            let mut st = self.conn.prepare_cached(
                "SELECT u.id, u.name, u.email, u.full_name, t.id FROM api_tokens t
                 JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?",
            )?;
            st.query_row([digest], |r| Ok((row_user(r)?, r.get::<_, i64>(4)?)))
                .optional()?
        };
        if let Some((u, tok_id)) = row {
            let t = now() as i64;
            let mut up = self.conn.prepare_cached(
                "UPDATE api_tokens SET last_used = ?1
                 WHERE id = ?2 AND (last_used IS NULL OR last_used < ?1 - 60)",
            )?;
            up.execute(rusqlite::params![t, tok_id])?;
            return Ok(Some(u));
        }
        Ok(None)
    }

    pub fn list_api_tokens(&self, user_id: i64) -> Result<Vec<ApiToken>> {
        let mut st = self.conn.prepare(
            "SELECT id, name, created_unix, last_used FROM api_tokens
             WHERE user_id = ? ORDER BY id DESC",
        )?;
        let rows = st.query_map([user_id], |r| {
            Ok(ApiToken {
                id: r.get(0)?,
                name: r.get(1)?,
                created_unix: r.get::<_, i64>(2)? as u64,
                last_used: r.get::<_, Option<i64>>(3)?.map(|t| t as u64),
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    /// Revoke a token — scoped to the owner so one user can't delete
    /// another's by guessing an id.
    pub fn revoke_api_token(&self, user_id: i64, token_id: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM api_tokens WHERE id = ? AND user_id = ?",
            rusqlite::params![token_id, user_id],
        )?;
        Ok(())
    }

    /// Set a new password (the caller verifies the old one via
    /// `verify_user` first).
    pub fn change_password(&self, user_id: i64, password: &str) -> Result<()> {
        if password.len() < 8 {
            return Err(Error::Query("password min 8 chars".into()));
        }
        let hash = hash_password(password)?;
        self.conn.execute(
            "UPDATE users SET pass_hash = ? WHERE id = ?",
            rusqlite::params![hash, user_id],
        )?;
        Ok(())
    }

    /// Update the account's email and display name — how accounts seeded
    /// before these columns existed (or registered with a blank email)
    /// gain them later. Blank email clears to `NULL`; a non-blank email
    /// must contain `@` and stays unique case-insensitively.
    pub fn update_profile(&self, user_id: i64, email: &str, full_name: &str) -> Result<User> {
        let email = clean_email(email)?;
        let full_name = clean_full_name(full_name);
        self.conn.execute(
            "UPDATE users SET email = ?, full_name = ? WHERE id = ?",
            rusqlite::params![email, full_name, user_id],
        )?;
        let (id, name) =
            self.conn
                .query_row("SELECT id, name FROM users WHERE id = ?", [user_id], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?;
        Ok(User {
            id,
            name,
            email,
            full_name,
        })
    }

    /// Seconds left on the account's login lock — 0 when free. `who` may
    /// be the username or email; unknown identifiers are free.
    pub fn login_lock_remaining(&self, who: &str) -> Result<u64> {
        let who = who.trim();
        let until: Option<i64> = self
            .conn
            .query_row(WHO_LOCK, [who, who], |r| r.get::<_, Option<i64>>(0))
            .optional()?
            .flatten();
        Ok(until.map(|u| (u - now() as i64).max(0) as u64).unwrap_or(0))
    }

    /// Count one failed password login for `who` (name or email);
    /// reaching `max` locks the account for `secs`. Returns lock seconds
    /// remaining — 0 either when the account is unknown or still under
    /// the threshold.
    pub fn record_login_fail(&self, who: &str, max: u32, secs: u64) -> Result<u64> {
        let who = who.trim();
        let Some((id, fails, lock_until)) = self
            .conn
            .query_row(WHO_FAILS, [who, who], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })
            .optional()?
        else {
            return Ok(0);
        };
        let t = now() as i64;
        if lock_until.is_some_and(|u| u > t) {
            return Ok((lock_until.unwrap() - t) as u64);
        }
        let fails = fails + 1;
        if fails >= max as i64 {
            self.conn.execute(
                "UPDATE users SET fail_count = 0, lock_until = ? WHERE id = ?",
                rusqlite::params![t + secs as i64, id],
            )?;
            return Ok(secs);
        }
        self.conn.execute(
            "UPDATE users SET fail_count = ? WHERE id = ?",
            rusqlite::params![fails, id],
        )?;
        Ok(0)
    }

    pub fn clear_login_fails(&self, who: &str) -> Result<()> {
        let who = who.trim();
        self.conn.execute(WHO_CLEAR, [who, who])?;
        Ok(())
    }

    pub fn set_totp(&self, user_id: i64, secret_b32: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE users SET totp_secret = ? WHERE id = ?",
            rusqlite::params![secret_b32, user_id],
        )?;
        Ok(())
    }

    pub fn clear_totp(&self, user_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE users SET totp_secret = NULL WHERE id = ?",
            [user_id],
        )?;
        Ok(())
    }

    /// The enrolled TOTP secret — `Some` means the login flow requires
    /// a code on top of the password.
    pub fn totp_secret(&self, user_id: i64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT totp_secret FROM users WHERE id = ?",
                [user_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }

    /// Live sessions for the account — expired rows swept first.
    pub fn list_sessions(&self, user_id: i64) -> Result<Vec<SessionInfo>> {
        let t = now() as i64;
        self.conn
            .execute("DELETE FROM sessions WHERE expires_unix < ?", [t])?;
        let mut st = self.conn.prepare(
            "SELECT token, created_unix, expires_unix FROM sessions
             WHERE user_id = ? ORDER BY created_unix DESC",
        )?;
        let rows = st.query_map([user_id], |r| {
            Ok(SessionInfo {
                token: r.get(0)?,
                created_unix: r.get::<_, i64>(1)? as u64,
                expires_unix: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    /// Revoke every session except `keep` — used on password change and
    /// "sign out other sessions".
    pub fn drop_other_sessions(&self, user_id: i64, keep: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND token != ?",
            rusqlite::params![user_id, keep],
        )?;
        Ok(())
    }

    /// Append an auth audit row. Events keep 90 days; the prune runs on
    /// each write so the table stays bounded.
    pub fn log_auth(&self, name: &str, ip: &str, event: &str) -> Result<()> {
        let t = now() as i64;
        self.conn.execute(
            "INSERT INTO auth_events (name, ip, event, unix_ts) VALUES (?,?,?,?)",
            rusqlite::params![name.trim(), ip, event, t],
        )?;
        self.conn.execute(
            "DELETE FROM auth_events WHERE unix_ts < ?",
            [t - 90 * 24 * 3600],
        )?;
        Ok(())
    }

    /// Newest `limit` audit rows for `name` — login attempts recorded
    /// under the attempted name show up for the account owner too.
    pub fn auth_events(&self, name: &str, limit: u32) -> Result<Vec<AuthEvent>> {
        let mut st = self.conn.prepare(
            "SELECT name, ip, event, unix_ts FROM auth_events
             WHERE name = ? ORDER BY unix_ts DESC LIMIT ?",
        )?;
        let rows = st.query_map(rusqlite::params![name.trim(), limit], |r| {
            Ok(AuthEvent {
                name: r.get(0)?,
                ip: r.get(1)?,
                event: r.get(2)?,
                unix_ts: r.get::<_, i64>(3)? as u64,
            })
        })?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn store() -> crate::Store {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(crate::SCHEMA).unwrap();
        conn.execute_batch(AUTH_SCHEMA).unwrap();
        crate::migrate(&conn).unwrap();
        crate::Store { conn }
    }

    #[test]
    fn user_session_token_roundtrip() {
        let s = store();
        assert_eq!(s.user_count().unwrap(), 0);
        let u = s
            .create_user("Alice", "alice@local.dev", "Alice A.", "hunter2hunter2")
            .unwrap();
        assert_eq!(u.name, "Alice");
        assert_eq!(u.email.as_deref(), Some("alice@local.dev"));
        assert_eq!(u.full_name.as_deref(), Some("Alice A."));
        // case-insensitive login by name or email, wrong password rejected
        let by_mail = s.verify_user("ALICE@local.dev", "hunter2hunter2").unwrap();
        assert_eq!(by_mail.as_ref().map(|u| u.id), Some(u.id));
        assert_eq!(
            s.verify_user("alice", "hunter2hunter2")
                .unwrap()
                .and_then(|u| u.email)
                .as_deref(),
            Some("alice@local.dev")
        );
        assert!(s.verify_user("alice", "wrong").unwrap().is_none());
        assert!(s.verify_user("bob", "hunter2hunter2").unwrap().is_none());
        // duplicate email (any case) is rejected like a duplicate name
        assert!(
            s.create_user("carol", "Alice@local.dev", "", "password123")
                .is_err()
        );
        // empty email/full_name store NULL; malformed email is rejected
        assert!(
            s.create_user("dave", "", "", "password123")
                .unwrap()
                .email
                .is_none()
        );
        assert!(
            s.create_user("erin", "not-an-email", "", "password123")
                .is_err()
        );

        let sess = s.create_session(u.id, 3600).unwrap();
        assert_eq!(s.user_for_session(&sess).unwrap().unwrap().id, u.id);
        s.drop_session(&sess).unwrap();
        assert!(s.user_for_session(&sess).unwrap().is_none());

        let tok = s.create_api_token(u.id, "extension").unwrap();
        assert!(tok.starts_with("ntok_"));
        assert_eq!(s.user_for_api_token(&tok).unwrap().unwrap().id, u.id);
        assert!(s.user_for_api_token("ntok_bogus").unwrap().is_none());
        let list = s.list_api_tokens(u.id).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].last_used.is_some());
        // another user can't revoke it
        let other = s.create_user("bob", "", "", "password123").unwrap();
        s.revoke_api_token(other.id, list[0].id).unwrap();
        assert_eq!(s.list_api_tokens(u.id).unwrap().len(), 1);
        s.revoke_api_token(u.id, list[0].id).unwrap();
        assert!(s.user_for_api_token(&tok).unwrap().is_none());
    }

    #[test]
    fn update_profile_sets_and_clears_email() {
        let s = store();
        // legacy-style account: no email, no display name
        let u = s.create_user("admin", "", "", "hunter2hunter2").unwrap();
        assert!(u.email.is_none());

        // gaining an email later — also usable as a login identifier
        let u2 = s
            .update_profile(u.id, "admin@local.dev", "The Admin")
            .unwrap();
        assert_eq!(u2.email.as_deref(), Some("admin@local.dev"));
        assert_eq!(u2.full_name.as_deref(), Some("The Admin"));
        assert_eq!(u2.name, "admin");
        assert!(
            s.verify_user("admin@local.dev", "hunter2hunter2")
                .unwrap()
                .is_some()
        );

        // invalid email rejected; duplicate email (any case) rejected
        assert!(s.update_profile(u.id, "not-an-email", "").is_err());
        s.create_user("bob", "bob@x.dev", "", "password123")
            .unwrap();
        assert!(s.update_profile(u.id, "BOB@x.dev", "").is_err());

        // blank email clears back to NULL; blank full_name clears too
        let u3 = s.update_profile(u.id, "", "").unwrap();
        assert!(u3.email.is_none() && u3.full_name.is_none());
    }

    #[test]
    fn lockout_totp_sessions_and_audit() {
        let s = store();
        let u = s
            .create_user("alice", "alice@x.dev", "", "hunter2hunter2")
            .unwrap();

        // per-user lock after `max` password fails — survives IP rotation,
        // and counts whether the attacker types the name or the email
        for _ in 0..2 {
            assert_eq!(s.record_login_fail("alice", 5, 60).unwrap(), 0);
        }
        for _ in 0..2 {
            assert_eq!(s.record_login_fail("alice@x.dev", 5, 60).unwrap(), 0);
        }
        assert_eq!(s.record_login_fail("alice", 5, 60).unwrap(), 60);
        assert!(s.login_lock_remaining("alice").unwrap() > 0);
        assert!(s.login_lock_remaining("alice@x.dev").unwrap() > 0);
        // unknown names never lock
        assert_eq!(s.login_lock_remaining("ghost").unwrap(), 0);
        s.clear_login_fails("alice@x.dev").unwrap();
        assert_eq!(s.login_lock_remaining("alice").unwrap(), 0);

        // TOTP enroll → a code generated at the current step verifies
        let sec = new_totp_secret();
        s.set_totp(u.id, &sec).unwrap();
        assert_eq!(s.totp_secret(u.id).unwrap().as_deref(), Some(sec.as_str()));
        let step = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 30;
        let code = totp_code(&sec, step).unwrap();
        assert!(totp_check(&sec, &code));
        assert!(!totp_check(&sec, "000000") || code == "000000");
        assert!(!totp_check(&sec, "abc"));
        s.clear_totp(u.id).unwrap();
        assert!(s.totp_secret(u.id).unwrap().is_none());

        // password change + session housekeeping
        s.change_password(u.id, "newpassword1").unwrap();
        assert!(s.verify_user("alice", "newpassword1").unwrap().is_some());
        let s1 = s.create_session(u.id, 3600).unwrap();
        let s2 = s.create_session(u.id, 3600).unwrap();
        assert_eq!(s.list_sessions(u.id).unwrap().len(), 2);
        s.drop_other_sessions(u.id, &s1).unwrap();
        assert_eq!(s.list_sessions(u.id).unwrap().len(), 1);
        assert!(s.user_for_session(&s2).unwrap().is_none());

        // audit log, newest first
        s.log_auth("alice", "127.0.0.1", "login_ok").unwrap();
        s.log_auth("alice", "10.0.0.9", "login_fail").unwrap();
        let ev = s.auth_events("alice", 10).unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].event, "login_fail");
        assert_eq!(ev[0].ip, "10.0.0.9");
    }
}
