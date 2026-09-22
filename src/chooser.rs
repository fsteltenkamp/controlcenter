//! A picker for a list, in the shape of the file browser: a group is a folder,
//! an entry is a file, and the same keys walk both.
//!
//! [`Picker`](crate::app::Picker) cycles through its options with `◂ ▸`, which
//! is right for the four forward types and hopeless once there are forty
//! tunnels. This is the other way to set the same field, over the same options,
//! so nothing about what is stored depends on which one was used.
//!
//! The top level is laid out the way every list in the program is — the
//! ungrouped entries, then each group in order of first appearance — and not
//! the file browser's folders-first, because the thing being picked from is one
//! of those lists and should look like it. It also puts "(none)" where the eye
//! already expects it.
//!
//! One thing it does that a directory cannot: typing at the top level searches
//! every folder at once. The reason to open this at all is usually that the
//! group an entry is filed under is the part you have forgotten, so making the
//! search go through the folders first would defeat it.

/// One thing that can be picked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    /// What the field is set to when this is picked.
    pub value: String,
    /// How it is listed inside its folder.
    pub name: String,
    /// The folder it is filed under. Empty = listed at the top level.
    pub folder: String,
}

impl Choice {
    /// An ungrouped choice, listed at the top level under its own name.
    pub fn plain(value: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            name: name.into(),
            folder: String::new(),
        }
    }

    pub fn in_folder(
        value: impl Into<String>,
        name: impl Into<String>,
        folder: impl Into<String>,
    ) -> Self {
        Self {
            value: value.into(),
            name: name.into(),
            folder: folder.into(),
        }
    }
}

/// A line in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    Folder(String),
    Choice {
        value: String,
        /// The name, with the folder in front of it when the row is being
        /// shown outside the folder it belongs to.
        label: String,
    },
}

#[derive(Debug, Clone)]
pub struct Chooser {
    /// What the popup is picking — "requires tunnel", "ssh host".
    pub title: String,
    choices: Vec<Choice>,
    /// The folder being listed. Empty = the top level.
    pub folder: String,
    /// What has been typed, which filters the listing.
    pub filter: String,
    pub rows: Vec<Row>,
    pub selected: usize,
}

impl Chooser {
    /// Open over `choices`, with `current` — the field's value — selected.
    /// Opening inside the current value's folder means the neighbours it was
    /// picked among are the first thing on screen.
    pub fn open(title: impl Into<String>, choices: Vec<Choice>, current: &str) -> Self {
        let folder = choices
            .iter()
            .find(|c| c.value == current)
            .map(|c| c.folder.clone())
            .unwrap_or_default();
        let mut c = Self {
            title: title.into(),
            choices,
            folder,
            filter: String::new(),
            rows: Vec::new(),
            selected: 0,
        };
        c.refresh();
        c.select_value(current);
        c
    }

    /// How many choices there are in all, for the count the popup shows.
    pub fn total(&self) -> usize {
        self.choices.len()
    }

    fn folders(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for c in &self.choices {
            if !c.folder.is_empty() && !out.contains(&c.folder) {
                out.push(c.folder.clone());
            }
        }
        out
    }

    fn refresh(&mut self) {
        let filter = self.filter.to_lowercase();
        let matches = |s: &str| filter.is_empty() || s.to_lowercase().contains(&filter);

        let mut rows: Vec<Row> = Vec::new();
        if self.folder.is_empty() {
            for c in &self.choices {
                // With nothing typed this is a tree and a grouped entry is
                // inside its folder; typing turns it into a search of the lot.
                let listed = if filter.is_empty() {
                    c.folder.is_empty()
                } else {
                    matches(&c.name)
                };
                if listed {
                    rows.push(Row::Choice {
                        value: c.value.clone(),
                        label: if c.folder.is_empty() {
                            c.name.clone()
                        } else {
                            format!("{} / {}", c.folder, c.name)
                        },
                    });
                }
            }
            rows.extend(
                self.folders()
                    .into_iter()
                    .filter(|f| matches(f))
                    .map(Row::Folder),
            );
        } else {
            for c in self.choices.iter().filter(|c| c.folder == self.folder) {
                if matches(&c.name) {
                    rows.push(Row::Choice {
                        value: c.value.clone(),
                        label: c.name.clone(),
                    });
                }
            }
        }
        self.rows = rows;
        if self.selected >= self.rows.len() {
            self.selected = self.rows.len().saturating_sub(1);
        }
    }

    fn select_value(&mut self, value: &str) {
        if let Some(i) = self
            .rows
            .iter()
            .position(|r| matches!(r, Row::Choice { value: v, .. } if v == value))
        {
            self.selected = i;
        }
    }

    pub fn push(&mut self, c: char) {
        self.filter.push(c);
        self.selected = 0;
        self.refresh();
    }

    /// Backspace edits the filter, and once there is none left it is the way
    /// back out of a folder — the same key doing the same thing it does in a
    /// path, where deleting the last segment is also how you go up.
    pub fn backspace(&mut self) {
        if self.filter.is_empty() {
            self.ascend();
            return;
        }
        self.filter.pop();
        self.selected = 0;
        self.refresh();
    }

    pub fn down(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + 1) % self.rows.len();
        }
    }

    pub fn up(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + self.rows.len() - 1) % self.rows.len();
        }
    }

    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    /// Walk into the selected folder. Choices are left to [`Self::accept`].
    pub fn descend(&mut self) {
        let Some(Row::Folder(name)) = self.selected_row().cloned() else {
            return;
        };
        self.folder = name;
        self.filter.clear();
        self.selected = 0;
        self.refresh();
    }

    /// Back to the top level, with the folder we came out of selected.
    pub fn ascend(&mut self) {
        if self.folder.is_empty() {
            return;
        }
        let leaf = std::mem::take(&mut self.folder);
        self.filter.clear();
        self.selected = 0;
        self.refresh();
        if let Some(i) = self
            .rows
            .iter()
            .position(|r| matches!(r, Row::Folder(f) if *f == leaf))
        {
            self.selected = i;
        }
    }

    /// Enter: walk into a folder, or hand back the picked value. `None` means
    /// the popup stays open.
    pub fn accept(&mut self) -> Option<String> {
        match self.selected_row().cloned() {
            Some(Row::Folder(_)) => {
                self.descend();
                None
            }
            Some(Row::Choice { value, .. }) => Some(value),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn choices() -> Vec<Choice> {
        vec![
            Choice::plain("", "(none)"),
            Choice::plain("loose", "loose"),
            Choice::in_folder("prod-db", "db", "prod"),
            Choice::in_folder("prod-web", "web", "prod"),
            Choice::in_folder("test-db", "db", "test"),
        ]
    }

    fn labels(c: &Chooser) -> Vec<String> {
        c.rows
            .iter()
            .map(|r| match r {
                Row::Folder(f) => format!("{f}/"),
                Row::Choice { label, .. } => label.clone(),
            })
            .collect()
    }

    #[test]
    fn the_top_level_is_what_is_in_no_group_and_then_the_groups() {
        // The same shape as every list in the program: ungrouped first.
        let c = Chooser::open("dep", choices(), "");
        assert_eq!(labels(&c), vec!["(none)", "loose", "prod/", "test/"]);
    }

    #[test]
    fn a_folder_lists_its_own_members_by_their_short_names() {
        let mut c = Chooser::open("dep", choices(), "");
        c.selected = 2; // prod/
        assert_eq!(c.accept(), None);
        assert_eq!(c.folder, "prod");
        assert_eq!(labels(&c), vec!["db", "web"]);
        assert_eq!(c.accept(), Some("prod-db".to_string()));
    }

    #[test]
    fn typing_at_the_top_level_searches_every_folder_at_once() {
        let mut c = Chooser::open("dep", choices(), "");
        for ch in "db".chars() {
            c.push(ch);
        }
        // Both "db" entries, each saying which group it came from.
        assert_eq!(labels(&c), vec!["prod / db", "test / db"]);
        assert_eq!(c.accept(), Some("prod-db".to_string()));
    }

    #[test]
    fn typing_inside_a_folder_stays_inside_it() {
        let mut c = Chooser::open("dep", choices(), "prod-web");
        assert_eq!(c.folder, "prod");
        for ch in "d".chars() {
            c.push(ch);
        }
        assert_eq!(labels(&c), vec!["db"]);
    }

    #[test]
    fn it_opens_on_the_value_the_field_already_holds() {
        let c = Chooser::open("dep", choices(), "test-db");
        assert_eq!(c.folder, "test");
        assert_eq!(
            c.selected_row(),
            Some(&Row::Choice {
                value: "test-db".into(),
                label: "db".into()
            })
        );
    }

    #[test]
    fn backspace_clears_the_filter_and_then_leaves_the_folder() {
        let mut c = Chooser::open("dep", choices(), "prod-db");
        c.push('w');
        assert_eq!(labels(&c), vec!["web"]);
        c.backspace();
        assert_eq!(labels(&c), vec!["db", "web"]);
        c.backspace();
        assert_eq!(c.folder, "");
        // And the folder it came out of is what the cursor is on.
        assert_eq!(c.selected_row(), Some(&Row::Folder("prod".into())));
    }

    #[test]
    fn a_search_that_matches_nothing_picks_nothing() {
        let mut c = Chooser::open("dep", choices(), "");
        for ch in "zzz".chars() {
            c.push(ch);
        }
        assert!(c.rows.is_empty());
        assert_eq!(c.accept(), None);
    }
}
