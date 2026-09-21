//! Prometheus metrics (`GET /metrics`), the industry-standard way for an admin to
//! watch a service from Grafana, Alertmanager or any monitoring stack.
//!
//! The endpoint needs the same sign-in as the rest of the console; a Prometheus
//! server scrapes it with an API token (`Authorization: Bearer dnt_…`, viewer role).
//! It exposes counts and health only: no device names, addresses or alert text.
//! The one label that could carry user text (a channel or export name) is escaped.

use std::fmt::Write;

/// One metric family being built.
pub struct Exposition {
    out: String,
}

/// Escape a label value as the text format requires: `\`, `"` and newline.
pub fn escape_label(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            c if c.is_control() => s.push(' '),
            c => s.push(c),
        }
    }
    s
}

impl Exposition {
    pub fn new() -> Self {
        Exposition { out: String::new() }
    }

    /// Start a family: `# HELP` and `# TYPE` lines.
    pub fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    /// One sample. `labels` are `(name, value)` pairs (values are escaped here).
    pub fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{k}=\"{}\"", escape_label(v));
            }
            self.out.push('}');
        }
        // integers print without a fraction; NaN/inf are not valid for our gauges
        if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
            let _ = writeln!(self.out, " {}", value as i64);
        } else if value.is_finite() {
            let _ = writeln!(self.out, " {value}");
        } else {
            let _ = writeln!(self.out, " 0");
        }
    }

    /// A family with a single unlabelled sample.
    pub fn gauge(&mut self, name: &str, help: &str, value: f64) {
        self.family(name, "gauge", help);
        self.sample(name, &[], value);
    }

    pub fn finish(self) -> String {
        self.out
    }
}

impl Default for Exposition {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_follow_the_text_format_and_labels_cannot_break_out() {
        let mut e = Exposition::new();
        e.gauge("denis_up", "1 while running", 1.0);
        e.family("denis_alerts", "gauge", "open alerts");
        e.sample("denis_alerts", &[("severity", "high")], 3.0);
        e.sample("denis_x", &[("name", "evil\"} 999\nfake_metric 1")], 0.5);
        let t = e.finish();
        assert!(t.contains("# TYPE denis_up gauge\ndenis_up 1\n"), "{t}");
        assert!(t.contains("denis_alerts{severity=\"high\"} 3\n"));
        assert!(t.contains("denis_x{name=\"evil\\\"} 999\\nfake_metric 1\"} 0.5\n"), "{t}");
        assert_eq!(t.lines().filter(|l| l.starts_with("fake_metric")).count(), 0, "no forged line");
        let mut e = Exposition::new();
        e.sample("denis_nan", &[], f64::NAN);
        assert_eq!(e.finish(), "denis_nan 0\n");
    }
}
