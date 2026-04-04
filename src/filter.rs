use std::collections::HashSet;
use std::io::{self, BufRead};
use std::path::Path;

pub struct Filter {
    blocked: HashSet<String>,
}

impl Filter {
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        Self {
            blocked: domains.into_iter().collect(),
        }
    }

    /// OISD domainswild2 形式のファイルからフィルタを読み込む。
    /// 1行1ドメイン、`#` で始まる行はコメント。
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut blocked = HashSet::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // 末尾のドットがあれば除去して正規化
            let domain = trimmed.trim_end_matches('.');
            blocked.insert(domain.to_lowercase());
        }

        Ok(Self { blocked })
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();
        let mut d = lower.as_str();
        loop {
            if self.blocked.contains(d) {
                return true;
            }
            match d.find('.') {
                Some(pos) => d = &d[pos + 1..],
                None => return false,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.blocked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_filter() -> Filter {
        Filter::new([
            "ads.example.com".into(),
            "tracking.example.com".into(),
            "doubleclick.net".into(),
            "evil.org".into(),
        ])
    }

    #[test]
    fn exact_match() {
        let f = test_filter();
        assert!(f.is_blocked("doubleclick.net"));
        assert!(f.is_blocked("ads.example.com"));
    }

    #[test]
    fn subdomain_match() {
        let f = test_filter();
        assert!(f.is_blocked("sub.doubleclick.net"));
        assert!(f.is_blocked("deep.sub.doubleclick.net"));
        assert!(f.is_blocked("foo.ads.example.com"));
    }

    #[test]
    fn no_false_positive_on_partial_label() {
        let f = test_filter();
        // "notdoubleclick.net" は "doubleclick.net" のサブドメインではない
        assert!(!f.is_blocked("notdoubleclick.net"));
        assert!(!f.is_blocked("notevil.org"));
    }

    #[test]
    fn non_blocked_domains() {
        let f = test_filter();
        assert!(!f.is_blocked("example.com"));
        assert!(!f.is_blocked("safe.example.com"));
        assert!(!f.is_blocked("google.com"));
    }

    #[test]
    fn case_insensitive() {
        let f = test_filter();
        assert!(f.is_blocked("DoubleClick.Net"));
        assert!(f.is_blocked("ADS.EXAMPLE.COM"));
    }

    #[test]
    fn empty_and_edge_cases() {
        let f = test_filter();
        assert!(!f.is_blocked(""));
        assert!(!f.is_blocked("com"));
        assert!(!f.is_blocked("net"));
    }

    #[test]
    fn from_file_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocklist.txt");
        std::fs::write(
            &path,
            "# comment\nads.example.com\n\ntracking.example.com\n  doubleclick.net  \n",
        )
        .unwrap();

        let f = Filter::from_file(&path).unwrap();
        assert_eq!(f.len(), 3);
        assert!(f.is_blocked("ads.example.com"));
        assert!(f.is_blocked("sub.doubleclick.net"));
        assert!(!f.is_blocked("example.com"));
    }
}
