//! AI usage visibility (AI.md section 23): a rough sense of how much any of the AI features have
//! actually been used, for an administrator who wants to know before a bill does. Deliberately
//! coarse — a call count and, when the provider's own response reported one, a token count, each
//! bucketed by day and by calendar month. Never blocks or gates anything; a write here only ever
//! happens after a real provider call already succeeded (see each call site in `web_ai.rs`/
//! `ai_summary.rs`), so a failure to record usage can never be why a feature stopped working.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::store::SettingsStore;

pub const KEY: &str = "ai_usage";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct UsageRecord {
    /// Epoch day (`now / 86400`, UTC) the day counters were last reset for.
    pub day: i64,
    pub day_calls: i64,
    /// Sums only the calls whose provider actually reported a token count; a `None` from `ai::ask`
    /// (a provider that does not report usage, or a shape this code does not recognise) simply
    /// contributes nothing rather than being guessed at.
    pub day_tokens: i64,
    /// `year * 12 + (month - 1)`, so it increments by exactly 1 each calendar month regardless of
    /// how many days that month has.
    pub month: i32,
    pub month_calls: i64,
    pub month_tokens: i64,
    pub last_call_at: i64,
}

fn day_key(now: i64) -> i64 {
    now.div_euclid(86400)
}

fn month_key(now: i64) -> i32 {
    let dt = time::OffsetDateTime::from_unix_timestamp(now).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    dt.year() * 12 + dt.month() as i32
}

pub fn load(store: &dyn SettingsStore) -> Result<UsageRecord> {
    let raw = store.get_setting(KEY)?;
    Ok(raw.as_deref().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default())
}

fn save(store: &dyn SettingsStore, r: &UsageRecord, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(r)?, now)
}

/// Records one successful AI call. `tokens`: that call's own token count, when the provider
/// reported one (see `ask`'s own doc in `ai.rs`) — `None` otherwise, not a guess.
pub fn record(store: &dyn SettingsStore, now: i64, tokens: Option<i64>) -> Result<()> {
    let mut r = load(store)?;
    let day = day_key(now);
    let month = month_key(now);
    if r.day != day {
        r.day = day;
        r.day_calls = 0;
        r.day_tokens = 0;
    }
    if r.month != month {
        r.month = month;
        r.month_calls = 0;
        r.month_tokens = 0;
    }
    r.day_calls += 1;
    r.month_calls += 1;
    if let Some(t) = tokens {
        r.day_tokens += t;
        r.month_tokens += t;
    }
    r.last_call_at = now;
    save(store, &r, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn a_fresh_record_starts_at_zero() {
        let s = SqliteStore::open_in_memory().unwrap();
        assert_eq!(load(&s).unwrap(), UsageRecord::default());
    }

    #[test]
    fn calls_and_tokens_accumulate_within_the_same_day_and_month() {
        let s = SqliteStore::open_in_memory().unwrap();
        let now = 1_700_000_000; // an arbitrary fixed instant, so the test is deterministic
        record(&s, now, Some(120)).unwrap();
        record(&s, now + 60, Some(80)).unwrap();
        record(&s, now + 120, None).unwrap(); // a call whose provider reported no usage
        let r = load(&s).unwrap();
        assert_eq!((r.day_calls, r.day_tokens, r.month_calls, r.month_tokens, r.last_call_at), (3, 200, 3, 200, now + 120));
    }

    #[test]
    fn a_new_day_resets_the_day_counters_but_not_the_month() {
        let s = SqliteStore::open_in_memory().unwrap();
        let day1 = 1_700_000_000;
        let day2 = day1 + 86400 * 2; // still the same month in practice for this fixed instant
        record(&s, day1, Some(50)).unwrap();
        record(&s, day2, Some(30)).unwrap();
        let r = load(&s).unwrap();
        assert_eq!((r.day_calls, r.day_tokens), (1, 30), "the day bucket rolled over");
        assert_eq!((r.month_calls, r.month_tokens), (2, 80), "the month bucket did not");
    }

    #[test]
    fn month_key_increments_by_exactly_one_each_calendar_month() {
        let jan = time::Date::from_calendar_date(2026, time::Month::January, 15).unwrap().midnight().assume_utc().unix_timestamp();
        let feb = time::Date::from_calendar_date(2026, time::Month::February, 1).unwrap().midnight().assume_utc().unix_timestamp();
        let dec_prev = time::Date::from_calendar_date(2025, time::Month::December, 31).unwrap().midnight().assume_utc().unix_timestamp();
        assert_eq!(month_key(feb) - month_key(jan), 1);
        assert_eq!(month_key(jan) - month_key(dec_prev), 1, "a year boundary is still exactly one month");
    }
}
