//! Session state: password template with Evomi flags, atomic rotation.
//!
//! Accepts a base password or a full dashboard string with flags, e.g.
//! `BASE_country-GB,US_session-Ab12Cd34_lifetime-15`. Rotation replaces
//! only the session-id segment (same session key), preserving other flags.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::SessionType;

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_hex4() -> String {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("RNG unavailable");
    format!("{:02x}{:02x}{:02x}{:02x}", buf[0], buf[1], buf[2], buf[3])
}

pub fn valid_session_id(s: &str) -> bool {
    (6..=10).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

struct Inner {
    head: String,
    tail: String,
    key: SessionType,
    id: String,
    generation: u64,
    rotated_at: u64,
}

pub struct SessionState {
    inner: Mutex<Inner>,
}

impl SessionState {
    pub fn new(template: &str) -> Result<Self, String> {
        let template = template.trim();
        if template.is_empty() || template.len() > 512 {
            return Err("password must be 1-512 chars".to_string());
        }
        let (head, key, id, tail) = split_session(template).unwrap_or_else(|| {
            (
                template.to_string(),
                SessionType::Session,
                random_hex4(),
                String::new(),
            )
        });
        let id = if valid_session_id(&id) { id } else { random_hex4() };
        Ok(SessionState {
            inner: Mutex::new(Inner {
                head,
                tail,
                key,
                id,
                generation: 0,
                rotated_at: now_s(),
            }),
        })
    }

    pub fn current_password(&self) -> String {
        let i = self.inner.lock().unwrap();
        format!("{}_{}-{}{}", i.head, i.key, i.id, i.tail)
    }

    pub fn label(&self) -> String {
        let i = self.inner.lock().unwrap();
        format!("{}-{} (gen {})", i.key, i.id, i.generation)
    }

    pub fn session_type(&self) -> SessionType {
        self.inner.lock().unwrap().key
    }

    /// Non-secret `_key-value` segments (base password never included).
    pub fn flags(&self) -> Vec<String> {
        let pw = self.current_password();
        let mut parts = pw.split('_');
        parts.next(); // base (secret)
        parts
            .filter(|p| p.contains('-'))
            .filter(|p| {
                // exclude the session-id segment itself
                let probe = format!("_{p}");
                !is_session_segment(&probe)
            })
            .map(|s| s.to_string())
            .collect()
    }

    pub fn lifetime_minutes(&self) -> Option<u32> {
        for flag in self.flags() {
            if let Some(v) = flag.strip_prefix("lifetime-") {
                let n: u32 = v.parse().ok()?;
                if (1..=1440).contains(&n) {
                    return Some(n);
                }
                return None;
            }
        }
        if self.session_type() == SessionType::Session {
            Some(30) // Evomi default for `session`
        } else {
            None
        }
    }

    pub fn expires_in_s(&self) -> Option<u64> {
        let life = self.lifetime_minutes()? as u64;
        let rotated = self.inner.lock().unwrap().rotated_at;
        Some(rotated.saturating_add(life * 60).saturating_sub(now_s()))
    }

    pub fn generation(&self) -> u64 {
        self.inner.lock().unwrap().generation
    }

    pub fn rotate(&self) -> String {
        let mut i = self.inner.lock().unwrap();
        i.id = random_hex4();
        i.generation += 1;
        i.rotated_at = now_s();
        format!("{}-{} (gen {})", i.key, i.id, i.generation)
    }

    /// Switch session type with a fresh id; lifetime flag dropped unless `session`.
    pub fn set_session_type(&self, key: SessionType) {
        let mut i = self.inner.lock().unwrap();
        if i.key == key {
            return;
        }
        i.key = key;
        i.id = random_hex4();
        i.generation += 1;
        i.rotated_at = now_s();
        if key != SessionType::Session {
            i.tail = strip_lifetime_flag(&i.tail);
            i.head = strip_lifetime_flag(&i.head);
        }
    }

    /// Set sticky lifetime (1-1440) or clear with None. Only kept for `session`.
    pub fn set_lifetime(&self, minutes: Option<u32>) -> Result<(), String> {
        if let Some(m) = minutes {
            if m == 0 || m > 1440 {
                return Err("lifetime must be 1-1440 minutes".to_string());
            }
        }
        let mut i = self.inner.lock().unwrap();
        // rebuild: drop existing lifetime flag from head/tail, append if set
        i.head = strip_lifetime_flag(&i.head);
        i.tail = strip_lifetime_flag(&i.tail);
        if let Some(m) = minutes {
            if i.key == SessionType::Session {
                i.tail.push_str(&format!("_lifetime-{m}"));
            }
        }
        i.rotated_at = now_s();
        Ok(())
    }
}

/// Split template into (head, key, id, tail) around the first session segment.
fn split_session(template: &str) -> Option<(String, SessionType, String, String)> {
    for key in ["hardsession", "lockedsession", "session"] {
        let needle = format!("_{key}-");
        if let Some(pos) = template.find(&needle) {
            let rest = &template[pos + needle.len()..];
            let end = rest.find('_').unwrap_or(rest.len());
            let id = &rest[..end];
            if id.is_empty() {
                continue;
            }
            return Some((
                template[..pos].to_string(),
                SessionType::from_key(key).unwrap(),
                id.to_string(),
                rest[end..].to_string(),
            ));
        }
    }
    None
}

fn is_session_segment(probe_with_underscore: &str) -> bool {
    for key in ["hardsession", "lockedsession", "session"] {
        let needle = format!("_{key}-");
        if let Some(rest) = probe_with_underscore.strip_prefix(needle.as_str()) {
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return true;
            }
        }
    }
    false
}

fn strip_lifetime_flag(s: &str) -> String {
    let mut parts: Vec<&str> = s.split('_').collect();
    parts.retain(|p| !p.starts_with("lifetime-"));
    let mut out = parts.join("_");
    if s.starts_with('_') && !out.starts_with('_') {
        out.insert(0, '_');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_preserved_on_rotate() {
        let s = SessionState::new("BASE_country-GB,US_session-Ab12Cd34_lifetime-15").unwrap();
        assert!(s.flags().contains(&"country-GB,US,AE,DE,FR,IT".to_string()) || s.flags().contains(&"country-GB,US".to_string()));
        assert_eq!(s.lifetime_minutes(), Some(15));
        let old = s.current_password();
        s.rotate();
        let new = s.current_password();
        assert_ne!(old, new);
        assert_eq!(new.matches("_session-").count(), 1);
        assert!(new.ends_with("_lifetime-15"));
        assert!(!new.contains("Ab12Cd34"));
    }

    #[test]
    fn plain_base_gets_session() {
        let s = SessionState::new("justbase").unwrap();
        assert!(s.current_password().starts_with("justbase_session-"));
        assert_eq!(s.lifetime_minutes(), Some(30));
    }

    #[test]
    fn hard_session_no_lifetime() {
        let s = SessionState::new("BASE_hardsession-JS9nsq2n").unwrap();
        assert_eq!(s.session_type(), SessionType::Hard);
        assert_eq!(s.lifetime_minutes(), None);
        s.rotate();
        assert!(s.current_password().contains("_hardsession-"));
    }

    #[test]
    fn set_type_drops_lifetime() {
        let s = SessionState::new("BASE_session-Ab12Cd34_lifetime-15").unwrap();
        s.set_session_type(SessionType::Hard);
        let pw = s.current_password();
        assert!(!pw.contains("lifetime"));
        assert!(pw.contains("_hardsession-"));
    }

    #[test]
    fn set_lifetime_roundtrip() {
        let s = SessionState::new("BASE").unwrap();
        s.set_lifetime(Some(60)).unwrap();
        assert_eq!(s.lifetime_minutes(), Some(60));
        assert!(s.current_password().contains("_lifetime-60"));
        s.set_lifetime(None).unwrap();
        assert_eq!(s.lifetime_minutes(), Some(30));
        assert!(s.set_lifetime(Some(0)).is_err());
        assert!(s.set_lifetime(Some(1441)).is_err());
    }
}
