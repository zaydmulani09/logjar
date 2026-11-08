//! Differential test of logjar's regex engine against the `regex` crate in
//! byte mode, on random patterns and random lines over a small alphabet
//! (small alphabets make matches, and so disagreements, likely).

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

const ATOMS: &[&str] = &[
    "a", "b", "1", "-", " ", r"\.", ".", r"\d", r"\w", r"\s", r"\D", "[ab]", "[^a1]", "[0-9-]",
    r"[\d.]", r"\x41",
];

fn gen(r: &mut Rng, depth: usize) -> String {
    let mut out = String::new();
    for _ in 0..1 + r.below(3) {
        let mut atom = if depth > 0 && r.below(4) == 0 {
            let mut alts = vec![gen(r, depth - 1)];
            if r.below(2) == 0 {
                alts.push(gen(r, depth - 1));
            }
            format!("({})", alts.join("|"))
        } else {
            ATOMS[r.below(ATOMS.len())].to_string()
        };
        match r.below(8) {
            0 => atom.push('*'),
            1 => atom.push('+'),
            2 => atom.push('?'),
            3 => {
                let m = r.below(3);
                atom.push_str(&match r.below(3) {
                    0 => format!("{{{m}}}"),
                    1 => format!("{{{m},}}"),
                    _ => format!("{{{m},{}}}", m + r.below(3)),
                });
            }
            _ => {}
        }
        out.push_str(&atom);
    }
    out
}

#[test]
fn agrees_with_regex_crate() {
    let mut r = Rng(0x0dd_ba11_cafe_f00d);
    let alphabet = b"ab1-. A\tz9";
    let mut matched = 0;
    for _ in 0..3000 {
        let mut pat = gen(&mut r, 2);
        if r.below(4) == 0 {
            pat.insert(0, '^');
        }
        if r.below(4) == 0 {
            pat.push('$');
        }
        let ic = r.below(4) == 0;
        let ours = logjar::Query::regex(&pat)
            .unwrap_or_else(|e| panic!("{pat:?}: {e}"))
            .ignore_case(ic);
        let flags = if ic { "(?s-u:(?i)" } else { "(?s-u:" };
        let theirs = regex::bytes::Regex::new(&format!("{flags}{pat})")).unwrap();
        for _ in 0..40 {
            let line: Vec<u8> = (0..r.below(12))
                .map(|_| alphabet[r.below(alphabet.len())])
                .collect();
            let want = theirs.is_match(&line);
            matched += want as usize;
            assert_eq!(
                ours.is_match(&line),
                want,
                "pattern {pat:?} ic={ic} line {:?}",
                String::from_utf8_lossy(&line)
            );
        }
    }
    // The generator should exercise both outcomes heavily.
    assert!(matched > 20_000 && matched < 100_000, "{matched}");
}
