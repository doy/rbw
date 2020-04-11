use chbs::scheme::ToScheme as _;
use rand::seq::SliceRandom as _;
use zeroize::Zeroize as _;

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

pub fn pwgen(ty: Type, len: usize) -> crate::locked::Vec {
    if ty == Type::Diceware {
        let mut locked_pass = crate::locked::Vec::new();
        let mut config = chbs::config::BasicConfig::default();
        config.words = len;
        config.capitalize_first = chbs::probability::Probability::Never;
        config.capitalize_words = chbs::probability::Probability::Never;
        let mut pass = config.to_scheme().generate();
        locked_pass.extend(pass.as_bytes().iter().copied());
        pass.zeroize();
        return locked_pass;
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
    let mut pass = crate::locked::Vec::new();
    pass.extend(alphabet.choose_multiple(&mut rng, len).copied());
    pass
}
