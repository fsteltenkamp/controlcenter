//! Log lines, and where a log pane gets them from.
//!
//! Every log pane in the program shows the same two things merged: what
//! controlcenter did about a connection, and what the process it started
//! printed. [`Journal`] holds the first, [`Ring`] the second, and [`LogTarget`]
//! says which connection a pane, an entry or an exported report is about.

use crate::vpn::ProviderId;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Lines kept per process. A tunnel that has been up for a week must not grow
/// without bound; short of that, keep enough that an exported log is the whole
/// story rather than its last page.
pub const RING_CAP: usize = 2000;
/// Entries kept in the journal, across every connection at once.
pub const JOURNAL_CAP: usize = 2000;

/// One line, with the time it was seen and what produced it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub at: SystemTime,
    /// `controlcenter` for something the program did, otherwise the program
    /// that printed the line — `ssh`, `openvpn`, `xfreerdp`.
    pub source: &'static str,
    pub text: String,
    /// Drawn in red, and marked in an exported report.
    pub error: bool,
}

/// What controlcenter itself says, as opposed to a child process.
pub const SELF: &str = "controlcenter";

/// A capped, thread-safe line buffer: the output of one child process.
///
/// The reader threads own no state of their own, so this is shared as an `Arc`
/// and pushed to from whichever thread is tailing the pipe.
pub struct Ring {
    source: &'static str,
    cap: usize,
    /// A deque rather than a Vec: a chatty process pushes a line at a time
    /// once the ring is full, and dropping the oldest should not shuffle the
    /// other two thousand along by one.
    lines: Mutex<VecDeque<Entry>>,
}

impl Ring {
    pub fn new(source: &'static str) -> Self {
        Self {
            source,
            cap: RING_CAP,
            lines: Mutex::new(VecDeque::new()),
        }
    }

    pub fn push(&self, text: impl Into<String>) {
        self.push_at(SystemTime::now(), text);
    }

    /// A line stamped with when its producer says it was written, which for a
    /// container's log is not when it reached us: a first look reads back
    /// hours of it at once.
    pub fn push_at(&self, at: SystemTime, text: impl Into<String>) {
        let mut lines = self.lines.lock().unwrap();
        if lines.len() >= self.cap {
            lines.pop_front();
        }
        lines.push_back(Entry {
            at,
            source: self.source,
            text: text.into(),
            error: false,
        });
    }

    /// The last `n` lines, oldest first.
    pub fn recent(&self, n: usize) -> Vec<Entry> {
        let lines = self.lines.lock().unwrap();
        lines.iter().rev().take(n).rev().cloned().collect()
    }

    pub fn all(&self) -> Vec<Entry> {
        self.lines.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.lines.lock().unwrap().clear();
    }

    /// The most recent line, for the one-line summaries in the status panes.
    pub fn last_text(&self) -> Option<String> {
        self.lines.lock().unwrap().back().map(|e| e.text.clone())
    }
}

/// Which connection a log pane, a journal entry or a report is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogTarget {
    /// controlcenter itself: everything it did, on every tab.
    Program,
    Tunnel(String),
    Ssh(String),
    Rdp(String),
    /// A VPN client, and the profile when the entry is about one. An empty
    /// profile means the client itself — a refresh, an install check.
    Vpn(ProviderId, String),
    /// A docker engine — empty for this machine, otherwise the SSH host it runs
    /// on — and the stack and container when the entry is about one. A
    /// container that belongs to no stack has an empty stack and a name.
    Docker {
        engine: String,
        stack: String,
        container: String,
    },
}

impl LogTarget {
    pub fn vpn(provider: ProviderId) -> Self {
        Self::Vpn(provider, String::new())
    }

    pub fn docker(engine: &str, stack: &str, container: &str) -> Self {
        Self::Docker {
            engine: engine.into(),
            stack: stack.into(),
            container: container.into(),
        }
    }

    /// How the pane titles it and the report names it.
    pub fn title(&self) -> String {
        match self {
            Self::Docker {
                engine,
                stack,
                container,
            } => {
                let on = if engine.is_empty() {
                    String::new()
                } else {
                    format!(" on '{engine}'")
                };
                match (stack.is_empty(), container.is_empty()) {
                    (_, false) => format!("container '{container}'{on}"),
                    (false, true) => format!("stack '{stack}'{on}"),
                    (true, true) if engine.is_empty() => "docker on this machine".into(),
                    (true, true) => format!("docker on '{engine}'"),
                }
            }
            Self::Program => "controlcenter".into(),
            Self::Tunnel(n) => format!("tunnel '{n}'"),
            Self::Ssh(n) => format!("ssh host '{n}'"),
            Self::Rdp(n) => format!("rdp connection '{n}'"),
            Self::Vpn(p, name) if name.is_empty() => p.slug().to_string(),
            Self::Vpn(p, name) => format!("{} profile '{name}'", p.slug()),
        }
    }

    /// The part of an exported report's filename that says what it is about.
    pub fn slug(&self) -> String {
        let raw = match self {
            // Not "controlcenter": every report's name starts with that already.
            Self::Program => "everything".into(),
            Self::Tunnel(n) => format!("tunnel-{n}"),
            Self::Ssh(n) => format!("ssh-{n}"),
            Self::Rdp(n) => format!("rdp-{n}"),
            Self::Vpn(p, name) if name.is_empty() => p.slug().to_string(),
            Self::Vpn(p, name) => format!("{}-{name}", p.slug()),
            Self::Docker {
                engine,
                stack,
                container,
            } => {
                let engine = if engine.is_empty() { "local" } else { engine };
                format!("docker-{engine}-{stack}-{container}")
            }
        };
        // A connection name is free text and ends up in a path.
        let mut slug: String = raw
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        while slug.contains("--") {
            slug = slug.replace("--", "-");
        }
        slug.trim_matches('-').to_string()
    }

    /// Whether a pane on `self` shows an entry recorded against `entry`.
    ///
    /// The program pane shows everything, and a VPN client's pane shows what
    /// its profiles did — a profile that would not come up is the client's
    /// story too.
    pub fn covers(&self, entry: &LogTarget) -> bool {
        match (self, entry) {
            (Self::Program, _) => true,
            (Self::Vpn(a, want), Self::Vpn(b, got)) => {
                a == b && (want.is_empty() || got.is_empty() || want == got)
            }
            // The same shape as a VPN client and its profiles, one level
            // deeper: an engine, a stack and a container each see what was
            // done to the others in their line, and never to a sibling.
            (
                Self::Docker {
                    engine: e1,
                    stack: s1,
                    container: c1,
                },
                Self::Docker {
                    engine: e2,
                    stack: s2,
                    container: c2,
                },
            ) => {
                let engine_level = |s: &str, c: &str| s.is_empty() && c.is_empty();
                e1 == e2
                    && (engine_level(s1, c1)
                        || engine_level(s2, c2)
                        || (s1 == s2 && (c1.is_empty() || c2.is_empty() || c1 == c2)))
            }
            (a, b) => a == b,
        }
    }
}

/// What controlcenter did, in order, across every connection.
#[derive(Default)]
pub struct Journal {
    entries: Vec<(LogTarget, Entry)>,
}

impl Journal {
    pub fn note(&mut self, target: LogTarget, text: impl Into<String>) {
        self.record(target, text.into(), false);
    }

    pub fn fail(&mut self, target: LogTarget, text: impl Into<String>) {
        self.record(target, text.into(), true);
    }

    fn record(&mut self, target: LogTarget, text: String, error: bool) {
        if self.entries.len() >= JOURNAL_CAP {
            self.entries.remove(0);
        }
        self.entries.push((
            target,
            Entry {
                at: SystemTime::now(),
                source: SELF,
                text,
                error,
            },
        ));
    }

    /// The entries a pane on `target` shows.
    pub fn entries_for(&self, target: &LogTarget) -> Vec<Entry> {
        self.entries
            .iter()
            .filter(|(t, _)| target.covers(t))
            .map(|(_, e)| e.clone())
            .collect()
    }

    /// Every entry, with what it was about — the whole story, for a report.
    pub fn all(&self) -> &[(LogTarget, Entry)] {
        &self.entries
    }

    pub fn clear_for(&mut self, target: &LogTarget) {
        self.entries.retain(|(t, _)| !target.covers(t));
    }
}

// ---------------------------------------------------------------------------
// Wall-clock time
//
// Everything else in the program measures with `Instant`, which is all a
// running TUI needs. A log line is read after the fact, so it needs a date, and
// UTC keeps that to arithmetic on the epoch rather than a dependency.
// ---------------------------------------------------------------------------

/// `2026-08-26 14:03:11 UTC` — how a report writes a time.
pub fn stamp(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = parts(t);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// `20260826-140311` — how a report's filename writes one.
pub fn file_stamp(t: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = parts(t);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// `14:03:11` — how a log pane prefixes a line.
pub fn clock(t: SystemTime) -> String {
    let (_, _, _, h, mi, s) = parts(t);
    format!("{h:02}:{mi:02}:{s:02}")
}

/// `2026-11-13T09:12:01.123456789Z`, as docker stamps a log line, into a time.
/// Only UTC is read, because that is all docker writes; anything else is not a
/// stamp and is left as part of the line.
pub fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };
    let mut t = hms.splitn(3, ':').map(|p| p.parse::<i64>().ok());
    let (h, mi, se) = (t.next()??, t.next()??, t.next()??);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    if !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let nanos: u32 = format!("{:0<9}", &frac[..frac.len().min(9)]).parse().ok()?;
    let secs = days_from_civil(y, mo as u32, da as u32) * 86_400 + h * 3600 + mi * 60 + se;
    let secs = u64::try_from(secs).ok()?;
    Some(UNIX_EPOCH + std::time::Duration::new(secs, nanos))
}

/// The inverse of [`civil_from_days`], from the same algorithm.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Split a time into UTC calendar parts. Times before the epoch cannot come
/// from a running process, so they are pinned to it rather than handled.
fn parts(t: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    (
        y,
        mo,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// Howard Hinnant's days-to-civil-date algorithm, with the era starting on
/// 0000-03-01 so leap days land at the end of a four-century cycle.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(epoch_secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(epoch_secs)
    }

    #[test]
    fn the_epoch_and_a_known_date_come_out_right() {
        assert_eq!(stamp(at(0)), "1970-01-01 00:00:00 UTC");
        // 2026-08-26 14:03:11 UTC.
        assert_eq!(stamp(at(1_787_752_991)), "2026-08-26 14:03:11 UTC");
        assert_eq!(file_stamp(at(1_787_752_991)), "20260826-140311");
        assert_eq!(clock(at(1_787_752_991)), "14:03:11");
    }

    #[test]
    fn a_leap_day_is_a_day_of_its_own() {
        // 2024-02-29 00:00:00 UTC.
        assert_eq!(stamp(at(1_709_164_800)), "2024-02-29 00:00:00 UTC");
        // And the century that is not a leap year: 2100-03-01.
        assert_eq!(stamp(at(4_107_542_400)), "2100-03-01 00:00:00 UTC");
    }

    #[test]
    fn a_ring_keeps_the_last_lines_and_drops_the_rest() {
        let ring = Ring::new("ssh");
        for i in 0..(RING_CAP + 10) {
            ring.push(format!("line {i}"));
        }
        let all = ring.all();
        assert_eq!(all.len(), RING_CAP);
        assert_eq!(all[0].text, "line 10");
        assert_eq!(ring.last_text().unwrap(), format!("line {}", RING_CAP + 9));
        assert_eq!(ring.recent(2).len(), 2);
        ring.clear();
        assert!(ring.all().is_empty());
    }

    #[test]
    fn a_pane_shows_its_own_entries_and_the_program_pane_shows_them_all() {
        let mut j = Journal::default();
        j.note(LogTarget::Tunnel("db".into()), "started");
        j.fail(LogTarget::Tunnel("web".into()), "refused");
        j.note(LogTarget::Program, "plan built");

        let db = j.entries_for(&LogTarget::Tunnel("db".into()));
        assert_eq!(db.len(), 1);
        assert_eq!(db[0].text, "started");
        assert_eq!(j.entries_for(&LogTarget::Program).len(), 3);
        assert!(j.entries_for(&LogTarget::Tunnel("web".into()))[0].error);
    }

    #[test]
    fn a_vpn_client_pane_shows_what_its_profiles_did() {
        let mut j = Journal::default();
        j.note(LogTarget::Vpn(ProviderId::Openvpn, "work".into()), "up");
        j.note(LogTarget::vpn(ProviderId::Openvpn), "refreshed");
        j.note(LogTarget::Vpn(ProviderId::Wireguard, "home".into()), "up");

        // The client itself sees both its own entries and its profiles'.
        assert_eq!(j.entries_for(&LogTarget::vpn(ProviderId::Openvpn)).len(), 2);
        // A profile sees its own, plus what the client did while it was up.
        let work = j.entries_for(&LogTarget::Vpn(ProviderId::Openvpn, "work".into()));
        assert_eq!(work.len(), 2);
        // And never another client's.
        assert_eq!(
            j.entries_for(&LogTarget::Vpn(ProviderId::Openvpn, "other".into()))
                .len(),
            1
        );
    }

    #[test]
    fn clearing_a_pane_leaves_the_other_panes_alone() {
        let mut j = Journal::default();
        j.note(LogTarget::Tunnel("db".into()), "started");
        j.note(LogTarget::Rdp("desk".into()), "connected");
        j.clear_for(&LogTarget::Tunnel("db".into()));
        assert_eq!(j.all().len(), 1);
        assert_eq!(j.all()[0].1.text, "connected");
    }

    #[test]
    fn a_docker_stamp_reads_back_as_the_time_it_names() {
        let t = parse_rfc3339("2026-08-26T14:03:11.25Z").unwrap();
        assert_eq!(stamp(t), "2026-08-26 14:03:11 UTC");
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().subsec_millis(),
            250
        );
        assert_eq!(stamp(parse_rfc3339("2100-03-01T00:00:00Z").unwrap()), "2100-03-01 00:00:00 UTC");
        assert!(parse_rfc3339("2026-08-26 14:03:11").is_none());
        assert!(parse_rfc3339("hello").is_none());
    }

    #[test]
    fn a_container_pane_sees_its_stack_and_engine_but_not_its_siblings() {
        let engine = LogTarget::docker("", "", "");
        let stack = LogTarget::docker("", "web", "");
        let one = LogTarget::docker("", "web", "web-1");
        let other = LogTarget::docker("", "web", "web-2");
        let loose = LogTarget::docker("", "", "lonely");
        assert!(engine.covers(&one) && one.covers(&engine));
        assert!(stack.covers(&one) && one.covers(&stack));
        assert!(!one.covers(&other));
        assert!(!stack.covers(&loose) && !loose.covers(&stack));
        assert!(engine.covers(&loose));
        assert!(!one.covers(&LogTarget::docker("box", "web", "web-1")));
        assert_eq!(one.title(), "container 'web-1'");
        assert_eq!(one.slug(), "docker-local-web-web-1");
    }

    #[test]
    fn a_name_with_spaces_and_slashes_still_makes_a_filename() {
        assert_eq!(LogTarget::Tunnel("DB / prod".into()).slug(), "tunnel-db-prod");
        assert_eq!(LogTarget::Program.slug(), "everything");
        assert_eq!(
            LogTarget::Vpn(ProviderId::Openvpn, "Work VPN".into()).slug(),
            "openvpn-work-vpn"
        );
    }
}
