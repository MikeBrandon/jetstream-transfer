//! A 256-word list for rendering device fingerprints as speakable phrases.
//!
//! Each word encodes exactly one byte, so a six-word phrase carries 48 bits of
//! the device id. That is the number a user actually compares when pairing, so
//! it — not the full 256-bit id — is the real bound on how hard it is to forge
//! a matching identity. 48 bits is far past what an attacker can grind out
//! during a pairing prompt that is on screen for a few seconds.
//!
//! Words are chosen to be short, common, and unambiguous when spoken over a
//! phone: no homophone pairs, no words that differ only by a plural, and
//! nothing that sounds like a letter or digit.

pub const WORD_COUNT: usize = 256;

/// Number of words shown in a human-comparable fingerprint.
pub const FINGERPRINT_WORDS: usize = 6;

pub static WORDS: [&str; WORD_COUNT] = [
    "acid", "acorn", "agent", "album", "alien", "alpha", "amber", "anchor", //
    "angel", "ankle", "apple", "april", "arch", "arena", "armor", "arrow", //
    "aspen", "atlas", "attic", "audio", "autumn", "avenue", "axis", "bacon", //
    "badge", "bagel", "baker", "balance", "bamboo", "banjo", "barrel", "basil", //
    "basin", "batch", "beacon", "beagle", "bean", "bear", "beaver", "bedrock", //
    "beetle", "bench", "berry", "bishop", "bison", "blade", "blanket", "blaze", //
    "blend", "blimp", "block", "blossom", "blues", "bobcat", "bolt", "bonus", //
    "boost", "border", "bottle", "boulder", "bounce", "bracket", "branch", "brass", //
    "brave", "bread", "breeze", "brick", "bridge", "bright", "bronze", "brook", //
    "brush", "bubble", "bucket", "buffalo", "bugle", "bundle", "bunker", "burden", //
    "butter", "button", "cabin", "cable", "cactus", "camel", "camera", "campus", //
    "canary", "candle", "canoe", "canvas", "canyon", "cargo", "carpet", "carrot", //
    "cascade", "cashew", "castle", "catalog", "cedar", "cello", "cement", "census", //
    "chalk", "chapel", "charm", "cheddar", "cherry", "chess", "chime", "chorus", //
    "cinema", "circus", "citrus", "clamp", "classic", "clay", "clever", "cliff", //
    "climate", "clinic", "clover", "cluster", "cobalt", "cobra", "cocoa", "coffee", //
    "comet", "compass", "condor", "copper", "coral", "cosmic", "cotton", "cougar", //
    "county", "cousin", "coyote", "crane", "crater", "crayon", "cricket", "crimson", //
    "crystal", "cubic", "cuckoo", "cupcake", "curtain", "custom", "cycle", "cymbal", //
    "dagger", "dahlia", "daisy", "dancer", "dapper", "dawn", "decade", "decoy", //
    "deluxe", "denim", "depot", "desert", "diamond", "diesel", "digital", "dinner", //
    "dolphin", "domain", "donkey", "donut", "dragon", "drift", "drummer", "duffel", //
    "duplex", "dynamo", "eagle", "easel", "echo", "eclipse", "edible", "effort", //
    "eggplant", "elastic", "elbow", "elder", "electric", "elegant", "elephant", "elixir", //
    "eleven", "ember", "emerald", "empire", "energy", "engine", "enigma", "ensign", //
    "envoy", "epoxy", "equal", "escape", "essay", "estate", "ether", "ethics", //
    "eureka", "evening", "exact", "exhale", "exile", "exotic", "expert", "fabric", //
    "falcon", "fanfare", "fantasy", "farmer", "fathom", "feather", "fedora", "fennel", //
    "ferry", "fiber", "fiddle", "figure", "filter", "finale", "finch", "fjord", //
    "flamingo", "flannel", "flask", "fleet", "flint", "floral", "fluent", "flute", //
    "foam", "fossil", "fountain", "fragile", "frame", "freedom", "fresco", "frisbee", //
    "frontier", "frost", "fuel", "fusion", "future", "fuzzy", "gadget", "galaxy", //
];

/// Look up the index of a word, for parsing a fingerprint a user typed back in.
///
/// Linear scan: this runs once per manual-pairing attempt, never in a hot path.
pub fn index_of(word: &str) -> Option<u8> {
    WORDS
        .iter()
        .position(|w| w.eq_ignore_ascii_case(word))
        .map(|i| i as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn word_list_is_exactly_one_byte_wide() {
        assert_eq!(WORDS.len(), 256);
    }

    #[test]
    fn words_are_unique() {
        let unique: HashSet<_> = WORDS.iter().collect();
        assert_eq!(unique.len(), WORDS.len(), "duplicate word in fingerprint list");
    }

    #[test]
    fn words_are_lowercase_ascii_and_speakable() {
        for w in WORDS {
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "{w:?} must be lowercase ascii"
            );
            assert!((3..=8).contains(&w.len()), "{w:?} has an awkward length");
        }
    }

    #[test]
    fn every_word_round_trips_through_its_index() {
        for (i, w) in WORDS.iter().enumerate() {
            assert_eq!(index_of(w), Some(i as u8));
        }
        assert_eq!(index_of("JETSTREAM"), None);
    }
}
