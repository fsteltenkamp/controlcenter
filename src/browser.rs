//! A small file picker for the path fields of the forms: a path you type at the
//! top, and the directory it points at listed below. The typed path is always
//! the source of truth — the listing follows it, and picking from the listing
//! only writes back into it.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct FileBrowser {
    /// The typed path, exactly as shown in the text field.
    pub input: String,
    /// The directory the listing came from, tilde already expanded.
    pub dir: PathBuf,
    /// Entries of `dir` whose name starts with the typed last segment,
    /// directories first.
    pub entries: Vec<Entry>,
    pub selected: usize,
    /// Why the listing is empty, when it is not simply "nothing matched".
    pub error: Option<String>,
}

impl FileBrowser {
    /// Open on `initial` — the field's current value, or the home directory
    /// when the field is still empty.
    pub fn open(initial: &str) -> Self {
        let input = if initial.trim().is_empty() {
            home()
                .map(|h| with_trailing_slash(&h))
                .unwrap_or_else(|| format!(".{SEP}"))
        } else {
            initial.to_string()
        };
        let mut b = Self {
            input,
            dir: PathBuf::new(),
            entries: Vec::new(),
            selected: 0,
            error: None,
        };
        b.refresh();
        b
    }

    /// Re-read the directory the typed path points at and filter it by the
    /// segment being typed.
    pub fn refresh(&mut self) {
        let (dir_part, filter) = split_input(&self.input);
        self.dir = expand_tilde(&dir_part);
        self.error = None;
        self.entries = match std::fs::read_dir(&self.dir) {
            Ok(rd) => {
                let mut out: Vec<Entry> = rd
                    .filter_map(Result::ok)
                    .map(|e| {
                        let name = e.file_name().to_string_lossy().into_owned();
                        // Follow symlinks: a link to a directory is one to walk into.
                        let is_dir = e.path().is_dir();
                        Entry { name, is_dir }
                    })
                    .filter(|e| starts_with_ci(&e.name, &filter))
                    .collect();
                sort_entries(&mut out);
                out
            }
            Err(e) => {
                self.error = Some(format!("{}: {}", self.dir.display(), e));
                Vec::new()
            }
        };
        if self.selected >= self.entries.len() {
            self.selected = self.entries.len().saturating_sub(1);
        }
    }

    pub fn push(&mut self, c: char) {
        self.input.push(c);
        self.selected = 0;
        self.refresh();
    }

    pub fn backspace(&mut self) {
        self.input.pop();
        self.selected = 0;
        self.refresh();
    }

    pub fn down(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
        }
    }

    pub fn up(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + self.entries.len() - 1) % self.entries.len();
        }
    }

    pub fn selected_entry(&self) -> Option<&Entry> {
        self.entries.get(self.selected)
    }

    /// Walk into the selected directory. Files are left to `accept`.
    pub fn descend(&mut self) {
        let Some(entry) = self.selected_entry().filter(|e| e.is_dir).cloned() else {
            return;
        };
        self.input = with_trailing_slash(&self.dir.join(&entry.name));
        self.selected = 0;
        self.refresh();
    }

    /// Go up one level, leaving the directory we came from selected.
    pub fn ascend(&mut self) {
        let leaf = self
            .dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        let Some(parent) = self.dir.parent().map(Path::to_path_buf) else {
            return;
        };
        self.input = with_trailing_slash(&parent);
        self.selected = 0;
        self.refresh();
        if let Some(leaf) = leaf {
            if let Some(i) = self.entries.iter().position(|e| e.name == leaf) {
                self.selected = i;
            }
        }
    }

    /// Enter: walk into a directory, or hand back the picked path. `None` means
    /// the browser stays open.
    pub fn accept(&mut self) -> Option<String> {
        match self.selected_entry().cloned() {
            Some(e) if e.is_dir => {
                self.descend();
                None
            }
            Some(e) => Some(self.dir.join(&e.name).to_string_lossy().into_owned()),
            // Nothing listed: take the typed path at its word — the form is
            // free to reject it.
            None => {
                let path = expand_tilde(&self.input);
                let s = path.to_string_lossy().into_owned();
                (!s.is_empty()).then_some(s)
            }
        }
    }
}

/// What separates the segments of a typed path.
///
/// Windows accepts either and people type both, so both are read; only one is
/// ever written back, and that is [`SEP`].
#[cfg(windows)]
const SEPARATORS: &[char] = &['/', '\\'];
#[cfg(not(windows))]
const SEPARATORS: &[char] = &['/'];

#[cfg(windows)]
const SEP: char = '\\';
#[cfg(not(windows))]
const SEP: char = '/';

/// Split a typed path into the directory to list and the segment being typed.
fn split_input(input: &str) -> (String, String) {
    let Some(cut) = input.rfind(SEPARATORS) else {
        // No separator yet: a bare name is relative to the working directory.
        return (".".to_string(), input.to_string());
    };
    let (dir, name) = input.split_at(cut);
    // Every separator is one byte, so the split is on a char boundary and the
    // separator itself is the first byte of the second half.
    let (sep, name) = name.split_at(1);
    let dir = if dir.is_empty() {
        // The path was rooted and its root is all that is left of it. The
        // separator that was typed is the one written back, so a path typed
        // one way does not come back the other.
        sep.to_string()
    } else if dir.ends_with(':') {
        // `C:` on its own is the working directory of that drive, which is not
        // what somebody typing `C:\` meant.
        format!("{dir}{sep}")
    } else {
        dir.to_string()
    };
    (dir, name.to_string())
}

/// Directories first, then case-insensitively by name — the order a file
/// manager lists them in.
fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

fn starts_with_ci(name: &str, prefix: &str) -> bool {
    prefix.is_empty() || name.to_lowercase().starts_with(&prefix.to_lowercase())
}

fn with_trailing_slash(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.ends_with(SEPARATORS) {
        s.into_owned()
    } else {
        format!("{s}{SEP}")
    }
}

fn home() -> Option<PathBuf> {
    crate::platform::home()
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        return home().unwrap_or_else(|| PathBuf::from(path));
    }
    match path.strip_prefix("~/") {
        Some(rest) => match home() {
            Some(h) => h.join(rest),
            None => PathBuf::from(path),
        },
        None => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trailing_slash_lists_the_directory_itself() {
        assert_eq!(
            split_input("/etc/ssh/"),
            ("/etc/ssh".to_string(), String::new())
        );
    }

    #[test]
    fn a_partial_name_filters_its_parent() {
        assert_eq!(
            split_input("/etc/ss"),
            ("/etc".to_string(), "ss".to_string())
        );
    }

    #[test]
    fn a_name_in_the_root_still_lists_the_root() {
        assert_eq!(split_input("/us"), ("/".to_string(), "us".to_string()));
    }

    #[test]
    fn folders_come_before_files() {
        let mut e = vec![
            Entry { name: "b.conf".into(), is_dir: false },
            Entry { name: "Zeta".into(), is_dir: true },
            Entry { name: "a.conf".into(), is_dir: false },
            Entry { name: "alpha".into(), is_dir: true },
        ];
        sort_entries(&mut e);
        let names: Vec<&str> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "Zeta", "a.conf", "b.conf"]);
    }

    #[test]
    fn filtering_ignores_case() {
        assert!(starts_with_ci("Documents", "doc"));
        assert!(starts_with_ci("anything", ""));
        assert!(!starts_with_ci("Documents", "x"));
    }

    #[test]
    fn listing_a_real_directory_finds_its_entries() {
        let dir = std::env::temp_dir().join("controlcenter-browser-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("key.pem"), b"x").unwrap();

        let mut b = FileBrowser::open(&format!("{}/", dir.display()));
        assert_eq!(
            b.entries,
            vec![
                Entry { name: "sub".into(), is_dir: true },
                Entry { name: "key.pem".into(), is_dir: false },
            ]
        );

        // Typing narrows the listing to the matching file, and Enter picks it.
        for c in "key".chars() {
            b.push(c);
        }
        assert_eq!(b.entries.len(), 1);
        assert_eq!(b.accept(), Some(dir.join("key.pem").to_string_lossy().into_owned()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_on_a_folder_walks_into_it_instead_of_picking_it() {
        let dir = std::env::temp_dir().join("controlcenter-browser-descend");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();

        let mut b = FileBrowser::open(&format!("{}/", dir.display()));
        assert_eq!(b.accept(), None);
        assert_eq!(b.input, with_trailing_slash(&dir.join("sub")));

        // And back out again, with the directory we left selected.
        b.ascend();
        assert_eq!(b.selected_entry().map(|e| e.name.as_str()), Some("sub"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn a_drive_root_lists_the_drive_and_not_its_working_directory() {
        assert_eq!(split_input(r"C:\"), (r"C:\".to_string(), String::new()));
        assert_eq!(
            split_input(r"C:\Users\fl"),
            (r"C:\Users".to_string(), "fl".to_string())
        );
        // Typed the other way round, which Windows also accepts.
        assert_eq!(
            split_input("C:/Users/fl"),
            ("C:/Users".to_string(), "fl".to_string())
        );
    }
}
