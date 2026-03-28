//! Verify Python msgpack CLsend decodes as Rust CLsend.
use sira::{Beat, CLsend, SVsend};

const PYTHON_CLPACK_HEX: &str = "83a168d94035613066643935626465373839343735613763363432373138323635323062343266393963303938316236306337326662626165643635323931373766653465a16182a474797065a46563686fa464617461a968656c6c6f20737374a177d92435353065383430302d653239622d343164342d613731362d343436363535343430303030";

#[test]
fn python_msgpack_clsend_decodes() {
    let bytes: Vec<u8> = (0..PYTHON_CLPACK_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&PYTHON_CLPACK_HEX[i..i + 2], 16).unwrap())
        .collect();
    let cl: CLsend = rmp_serde::from_slice(&bytes).expect("decode CLsend");
    assert_eq!(cl.w, "550e8400-e29b-41d4-a716-446655440000");
    assert!(rmp_serde::from_slice::<Beat>(&bytes).is_err());
}

#[test]
fn svsend_msgpack_is_map_not_array() {
    let v = SVsend {
        h: "hh".into(),
        r: serde_json::json!({ "k": 1 }),
        w: "ww".into(),
        s: None,
    };
    let b = rmp_serde::to_vec_named(&v).unwrap();
    let fb = b[0];
    assert!(
        (0x80..=0x8f).contains(&fb),
        "SVsend should encode as fixmap (got first byte {:02x})",
        fb
    );
}
