//! A list of known-bad IPv4 addresses and networks (a "blocklist") that the
//! `threat_list_match` rule checks every outside address a device contacts against.
//!
//! The list is a plain text file the administrator supplies and refreshes, one entry
//! per line: an address (`203.0.113.9`) or a network (`198.51.100.0/24`). Blank lines
//! and comments (`# …`, `; …`, or text after the address) are ignored. That is the format of the
//! free lists published by abuse.ch (Feodo Tracker, URLhaus), Spamhaus DROP and
//! similar. DENIS ships no list and fetches nothing from the internet by itself.
//!
//! Entries are merged into sorted, non-overlapping ranges, so a lookup is a binary
//! search and a list of hundreds of thousands of entries costs a few megabytes.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// Refuse absurd files: a blocklist has at most a few hundred thousand entries.
const MAX_ENTRIES: usize = 1_000_000;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ThreatList {
    /// Sorted, non-overlapping inclusive `(first, last)` ranges.
    ranges: Vec<(u32, u32)>,
    /// How many entries the file had (before merging), for the console.
    pub entries: usize,
}

impl ThreatList {
    pub fn parse(text: &str) -> Result<Self> {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut entries = 0usize;
        for (n, line) in text.lines().enumerate() {
            let entry = line.split(['#', ';']).next().unwrap_or("").split_whitespace().next().unwrap_or("");
            if entry.is_empty() {
                continue;
            }
            let (addr, bits) = match entry.split_once('/') {
                Some((a, b)) => (a, b.parse::<u32>().ok().filter(|b| *b <= 32)),
                None => (entry, Some(32)),
            };
            let (Ok(ip), Some(bits)) = (addr.parse::<Ipv4Addr>(), bits) else {
                // a header line such as "ip_address" is normal; a real mistake elsewhere is not
                if n < 3 {
                    continue;
                }
                bail!("line {} is not an IPv4 address or network: {:?}", n + 1, entry.chars().take(40).collect::<String>());
            };
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let first = u32::from(ip) & mask;
            ranges.push((first, first | !mask));
            entries += 1;
            if entries > MAX_ENTRIES {
                bail!("more than {MAX_ENTRIES} entries");
            }
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (a, b) in ranges {
            match merged.last_mut() {
                Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        Ok(ThreatList { ranges: merged, entries })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path).with_context(|| format!("reading the threat list {}", path.display()))?;
        if meta.len() > MAX_FILE_BYTES {
            bail!("the threat list is larger than {} MB", MAX_FILE_BYTES / 1024 / 1024);
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("reading the threat list {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        match self.ranges.binary_search_by(|(a, _)| a.cmp(&v)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => self.ranges[i - 1].1 >= v,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn addresses_networks_comments_and_headers_are_understood() {
        let t = ThreatList::parse("# Feodo tracker\nip_address\n203.0.113.9\n198.51.100.0/24 ; a botnet net\n\n  192.0.2.7   # c2 server\n10.0.0.0/8\n").unwrap();
        assert_eq!(t.entries, 4);
        for hit in ["203.0.113.9", "198.51.100.0", "198.51.100.255", "192.0.2.7", "10.9.9.9"] {
            assert!(t.contains(ip(hit)), "{hit}");
        }
        for miss in ["203.0.113.8", "203.0.113.10", "198.51.101.0", "198.51.99.255", "192.0.2.6", "192.0.2.8", "11.0.0.0", "0.0.0.0", "255.255.255.255"] {
            assert!(!t.contains(ip(miss)), "{miss}");
        }
    }

    #[test]
    fn overlapping_and_adjacent_entries_merge_and_the_edges_of_the_address_space_work() {
        let t = ThreatList::parse("10.0.0.0/24\n10.0.0.128/25\n10.0.1.0/24\n0.0.0.0/32\n255.255.255.255\n").unwrap();
        assert_eq!(t.ranges.len(), 3, "{:?}", t.ranges);
        assert!(t.contains(ip("10.0.1.255")) && !t.contains(ip("10.0.2.0")));
        assert!(t.contains(ip("0.0.0.0")) && t.contains(ip("255.255.255.255")));
        assert!(ThreatList::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")), "an explicit /0 means everything");
    }

    #[test]
    fn mistakes_are_reported_with_the_line_number_but_never_panic() {
        for bad in ["1.1.1.1\n2.2.2.2\n3.3.3.3\nnot-an-ip\n", "1.1.1.1\n2.2.2.2\n3.3.3.3\n1.2.3.4/33\n", "1.1.1.1\n2.2.2.2\n3.3.3.3\n999.1.1.1\n"] {
            let e = ThreatList::parse(bad).unwrap_err().to_string();
            assert!(e.contains("line 4"), "{e}");
        }
        assert!(ThreatList::parse("").unwrap().is_empty());
        for junk in ["\u{0}\u{0}", "/", "1.1.1.1/", "//", "::1", "\r\n\r\n"] {
            let _ = ThreatList::parse(junk); // fuzz-ish: must not panic
        }
    }

    #[test]
    fn a_missing_file_is_a_clear_error() {
        let e = format!("{:#}", ThreatList::load(Path::new("/nonexistent/list.txt")).unwrap_err());
        assert!(e.contains("/nonexistent/list.txt"), "{e}");
    }
}
