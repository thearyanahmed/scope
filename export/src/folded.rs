//! Folded stacks (`frame;frame;frame weight`), the input format of
//! flamegraph.pl and inferno. See <https://github.com/brendangregg/FlameGraph#2-fold-stacks>.

use std::collections::BTreeMap;
use telemetry::StackSample;

/// Frames may contain anything a symbolizer produced; ';' and newlines would
/// break the format, so they are replaced.
fn clean(f: &str) -> String {
    f.chars().map(|c| if c == ';' || c == '\n' || c == '\r' { '_' } else { c }).collect()
}

/// Merge samples into folded lines, sorted for stable output.
/// `prefix` adds leading frames (e.g. thread name) per sample.
pub fn fold<'a>(samples: impl IntoIterator<Item = &'a StackSample>, prefix: impl Fn(&StackSample) -> Vec<String>) -> Vec<String> {
    let mut acc: BTreeMap<String, u64> = BTreeMap::new();
    for s in samples {
        let frames: Vec<String> = prefix(s).iter().chain(&s.frames).map(|f| clean(f)).collect();
        if frames.is_empty() {
            continue;
        }
        *acc.entry(frames.join(";")).or_insert(0) += s.weight;
    }
    acc.into_iter().map(|(k, v)| format!("{k} {v}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use telemetry::StackKind;

    fn s(frames: &[&str], w: u64) -> StackSample {
        StackSample { tid: 1, thread: "fc_vcpu 0".into(), kind: StackKind::Vmm, frames: frames.iter().map(|f| f.to_string()).collect(), weight: w }
    }

    #[test]
    fn merges_and_prefixes() {
        let v = [s(&["main", "run"], 2), s(&["main", "run"], 3), s(&["main", "a;b"], 1)];
        let out = fold(&v, |x| vec![x.thread.clone()]);
        assert_eq!(out, ["fc_vcpu 0;main;a_b 1", "fc_vcpu 0;main;run 5"]);
    }
}
