//! Pairing codes and browser sessions.
//!
//! # The threat this defends against
//!
//! The server is on a shared network with no transport security, so anyone who
//! can reach the port can try to talk to it. Port scanning is trivial. The only
//! thing standing between a stranger and the upload endpoint is a secret they
//! cannot guess, so:
//!
//! - Codes are 128 bits from the OS random source. Not a PIN — a six-digit code
//!   is guessable in under a second at LAN speeds, and rate limiting a UDP-fast
//!   local attacker is not a game worth playing.
//! - A code is **single use**. Scanning it exchanges it for a session; a second
//!   attempt with the same code fails. A QR left visible on screen after
//!   pairing is therefore spent, not a standing invitation.
//! - Codes expire whether used or not.
//! - Comparison is constant-time, so timing cannot be used to recover a code
//!   byte by byte.
//!
//! Session cookies are `HttpOnly` and `SameSite=Strict`. They cannot be
//! `Secure`, because the connection is plain HTTP and a `Secure` cookie would
//! simply never be sent — marking it so would be theatre.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use jetstream_core::proto::sanitize_name;

use crate::{CODE_LIFETIME, SESSION_LIFETIME};

/// Name of the session cookie.
pub const COOKIE: &str = "jetstream_session";

/// A code to show as a QR, plus the URL it encodes.
#[derive(Debug, Clone)]
pub struct PairingCode {
    pub token: String,
    pub url: String,
    pub expires_in: std::time::Duration,
}

/// Who is on the other end of a browser session.
#[derive(Debug, Clone)]
pub struct GuestInfo {
    /// Best-effort label from the User-Agent, e.g. `"iPhone"`. Cosmetic only —
    /// a browser can claim anything, so this is never a security input.
    pub label: String,
    pub address: String,
}

struct Code {
    token: String,
    issued: Instant,
}

struct Session {
    guest: GuestInfo,
    started: Instant,
}

pub struct Sessions {
    codes: Mutex<Vec<Code>>,
    sessions: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            codes: Mutex::new(Vec::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a new pairing code.
    pub fn issue_code(&self, base_url: &str) -> PairingCode {
        let token = random_token();

        let mut codes = self.codes.lock().expect("codes poisoned");
        codes.retain(|code| code.issued.elapsed() < CODE_LIFETIME);
        codes.push(Code {
            token: token.clone(),
            issued: Instant::now(),
        });

        PairingCode {
            url: format!("{base_url}/j/{token}"),
            token,
            expires_in: CODE_LIFETIME,
        }
    }

    /// Exchange a code for a session id, consuming the code.
    pub fn redeem(&self, token: &str, guest: GuestInfo) -> Option<String> {
        let mut codes = self.codes.lock().expect("codes poisoned");
        codes.retain(|code| code.issued.elapsed() < CODE_LIFETIME);

        let position = codes
            .iter()
            .position(|code| constant_time_eq(&code.token, token))?;
        codes.remove(position);
        drop(codes);

        let id = random_token();
        self.sessions.lock().expect("sessions poisoned").insert(
            id.clone(),
            Session {
                guest,
                started: Instant::now(),
            },
        );

        Some(id)
    }

    /// Resolve a session cookie, or `None` if it is unknown or expired.
    pub fn lookup(&self, id: &str) -> Option<GuestInfo> {
        let mut sessions = self.sessions.lock().expect("sessions poisoned");
        sessions.retain(|_, session| session.started.elapsed() < SESSION_LIFETIME);

        sessions.get(id).map(|session| session.guest.clone())
    }

    pub fn active_count(&self) -> usize {
        let mut sessions = self.sessions.lock().expect("sessions poisoned");
        sessions.retain(|_, session| session.started.elapsed() < SESSION_LIFETIME);
        sessions.len()
    }
}

/// 128 bits from the operating system's CSPRNG, hex encoded.
///
/// Straight from `getrandom` — `BCryptGenRandom` on Windows, `getrandom(2)` on
/// Linux — with no mixing, stretching, or cleverness of ours in between. A
/// bearer token is key material, and hand-rolled PRNG constructions over a
/// hash-map seed are exactly how that goes wrong.
///
/// Panics if the OS cannot supply randomness. That is the correct response:
/// issuing a guessable pairing code would silently expose the user's files,
/// which is far worse than refusing to start the browser receiver.
fn random_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .expect("the OS random source must be available to issue a pairing code");
    hex::encode(bytes)
}

/// Compare two tokens without leaking their contents through timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Derive a friendly label from a User-Agent string.
///
/// Cosmetic: it lets the accept prompt say "iPhone wants to send you files"
/// rather than "a browser". Untrusted input, so it goes through the same
/// sanitizer as any peer-supplied name and is matched against a fixed list
/// rather than parsed.
pub fn label_from_user_agent(agent: &str) -> String {
    const KNOWN: &[(&str, &str)] = &[
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android device"),
        ("Macintosh", "Mac"),
        ("Mac OS X", "Mac"),
        ("CrOS", "Chromebook"),
        ("Linux", "Linux device"),
        ("Windows", "Windows PC"),
    ];

    let matched = KNOWN
        .iter()
        .find(|(needle, _)| agent.contains(needle))
        .map(|(_, label)| *label)
        .unwrap_or("Browser");

    sanitize_name(matched)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guest() -> GuestInfo {
        GuestInfo {
            label: "iPhone".into(),
            address: "192.168.1.20".into(),
        }
    }

    #[test]
    fn a_code_can_be_redeemed_exactly_once() {
        let sessions = Sessions::new();
        let code = sessions.issue_code("http://192.168.1.6:5000");

        assert!(sessions.redeem(&code.token, guest()).is_some());
        assert!(
            sessions.redeem(&code.token, guest()).is_none(),
            "a spent code must not work twice — a QR left on screen is not a standing invitation"
        );
    }

    #[test]
    fn an_unknown_code_is_refused() {
        let sessions = Sessions::new();
        sessions.issue_code("http://192.168.1.6:5000");

        assert!(sessions.redeem("not-a-real-token", guest()).is_none());
        assert!(sessions.redeem("", guest()).is_none());
    }

    #[test]
    fn redeeming_yields_a_session_that_resolves() {
        let sessions = Sessions::new();
        let code = sessions.issue_code("http://192.168.1.6:5000");
        let id = sessions.redeem(&code.token, guest()).unwrap();

        assert_eq!(sessions.lookup(&id).unwrap().label, "iPhone");
        assert_eq!(sessions.active_count(), 1);
    }

    #[test]
    fn an_unknown_session_cookie_resolves_to_nothing() {
        let sessions = Sessions::new();
        assert!(sessions.lookup("00000000000000000000000000000000").is_none());
    }

    #[test]
    fn several_codes_can_be_outstanding() {
        // The user may open the panel on two devices before scanning either.
        let sessions = Sessions::new();
        let first = sessions.issue_code("http://x");
        let second = sessions.issue_code("http://x");

        assert!(sessions.redeem(&second.token, guest()).is_some());
        assert!(sessions.redeem(&first.token, guest()).is_some());
    }

    #[test]
    fn tokens_are_long_and_unpredictable() {
        let mut seen = std::collections::HashSet::new();

        for _ in 0..500 {
            let token = random_token();
            assert_eq!(token.len(), 32, "128 bits, hex encoded");
            assert!(
                seen.insert(token),
                "token collision — the random source is not doing its job"
            );
        }
    }

    #[test]
    fn the_pairing_url_contains_the_token() {
        let sessions = Sessions::new();
        let code = sessions.issue_code("http://192.168.1.6:5000");

        assert_eq!(code.url, format!("http://192.168.1.6:5000/j/{}", code.token));
    }

    #[test]
    fn token_comparison_is_length_safe() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn user_agents_become_friendly_labels() {
        assert_eq!(
            label_from_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"),
            "iPhone"
        );
        assert_eq!(
            label_from_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
            "Mac"
        );
        assert_eq!(
            label_from_user_agent("Mozilla/5.0 (Linux; Android 14; Pixel 8)"),
            "Android device"
        );
        assert_eq!(label_from_user_agent("curl/8.0"), "Browser");
    }

    #[test]
    fn a_hostile_user_agent_cannot_inject_through_the_label() {
        // The label reaches a prompt the user acts on, so it must not be able to
        // carry control characters or bidi overrides.
        let label = label_from_user_agent("\u{202E}iPhone\n\r");
        assert!(!label.contains('\u{202E}'));
        assert!(!label.contains('\n'));
    }
}
