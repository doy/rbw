use rand::seq::SliceRandom as _;

const SYMBOLS: &[u8] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const NUMBERS: &[u8] = b"0123456789";
const LETTERS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NONCONFUSABLES: &[u8] = b"34678abcdefhjkmnpqrtuwxy";

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Type {
    AllChars,
    NoSymbols,
    Numbers,
    NonConfusables,
    Diceware,
}

#[must_use]
pub fn pwgen(ty: Type, len: usize) -> String {
    let mut rng = rand::thread_rng();

    let alphabet = match ty {
        Type::AllChars => {
            let mut v = vec![];
            v.extend(SYMBOLS.iter().copied());
            v.extend(NUMBERS.iter().copied());
            v.extend(LETTERS.iter().copied());
            v
        }
        Type::NoSymbols => {
            let mut v = vec![];
            v.extend(NUMBERS.iter().copied());
            v.extend(LETTERS.iter().copied());
            v
        }
        Type::Numbers => {
            let mut v = vec![];
            v.extend(NUMBERS.iter().copied());
            v
        }
        Type::NonConfusables => {
            let mut v = vec![];
            v.extend(NONCONFUSABLES.iter().copied());
            v
        }
        Type::Diceware => {
            return diceware(&mut rng, len);
        }
    };

    let mut pass = vec![];
    pass.extend(
        std::iter::repeat_with(|| alphabet.choose(&mut rng).unwrap())
            .take(len),
    );
    // unwrap is safe because the method of generating passwords guarantees
    // valid utf8
    String::from_utf8(pass).unwrap()
}

fn diceware(rng: &mut impl rand::RngCore, len: usize) -> String {
    let mut words = vec![];
    for _ in 0..len {
        // unwrap is safe because choose only returns None for an empty slice
        words.push(*crate::wordlist::EFF_LONG.choose(rng).unwrap());
    }
    words.join(" ")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pwgen() {
        let pw = pwgen(Type::AllChars, 50);
        assert_eq!(pw.len(), 50);
        // technically this could fail, but the chances are incredibly low
        // (around 0.000009%)
        assert_duplicates(&pw);

        let pw = pwgen(Type::AllChars, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);

        let pw = pwgen(Type::NoSymbols, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);

        let pw = pwgen(Type::Numbers, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);

        let pw = pwgen(Type::NonConfusables, 100);
        assert_eq!(pw.len(), 100);
        assert_duplicates(&pw);
    }

    #[track_caller]
    fn assert_duplicates(s: &str) {
        let mut set = std::collections::HashSet::new();
        for c in s.chars() {
            set.insert(c);
        }
        assert!(set.len() < s.len());
    }
}
