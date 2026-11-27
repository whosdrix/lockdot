use lockdot::dotenv::{Item, parse, parse_vars, quote, render};
use proptest::prelude::*;

fn key() -> impl Strategy<Value = String> {
    "[A-Za-z_][A-Za-z0-9_]{0,20}"
}

proptest! {
    #[test]
    fn quote_roundtrips(k in key(), v in any::<String>()) {
        let text = format!("{k}={}\n", quote(&v));
        let vars = parse_vars(&text).unwrap();
        prop_assert_eq!(vars, vec![(k, v)]);
    }

    #[test]
    fn render_roundtrips(items in prop::collection::vec(
        prop_oneof![
            Just(Item::Blank),
            "[^\n\r]{0,30}".prop_map(Item::Comment),
            (key(), any::<String>()).prop_map(|(key, value)| Item::Var { key, value }),
        ],
        0..12,
    )) {
        let items: Vec<Item> = items.into_iter().map(|i| match i {
            Item::Comment(c) => Item::Comment(c.trim_end().to_string()),
            other => other,
        }).collect();
        let text = render(&items);
        let parsed = parse(&text).unwrap();
        let normalize = |v: &[Item]| v.iter().map(|i| match i {
            Item::Comment(c) => Item::Comment(c.trim().to_string()),
            other => other.clone(),
        }).collect::<Vec<_>>();
        prop_assert_eq!(normalize(&parsed), normalize(&items));
    }

    #[test]
    fn parser_never_panics(s in any::<String>()) {
        let _ = parse(&s);
    }
}
