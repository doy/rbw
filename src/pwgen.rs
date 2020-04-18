use chbs::scheme::ToScheme as _;
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

pub fn pwgen(ty: Type, len: usize) -> String {
    if ty == Type::Diceware {
        let mut config = chbs::config::BasicConfig::default();
        config.words = len;
        config.capitalize_first = chbs::probability::Probability::Never;
        config.capitalize_words = chbs::probability::Probability::Never;
        return config.to_scheme().generate();
    }

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
        Type::Diceware => unreachable!(),
    };

    let mut rng = rand::thread_rng();
    let mut pass = vec![];
    pass.extend(alphabet.choose_multiple(&mut rng, len).copied());
    // unwrap is safe because the method of generating passwords guarantees
    // valid utf8
    String::from_utf8(pass).unwrap()
}
