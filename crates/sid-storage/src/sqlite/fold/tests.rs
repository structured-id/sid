use super::simple_lowercase;

/// `simple_lowercase` takes the first code point of the full mapping; that is
/// the simple mapping only while U+0130 is the one code point whose full
/// lowercase is several. A Unicode update breaking that fails here.
#[test]
fn only_u0130_lowercases_to_several_code_points() {
    let several: Vec<char> = (0..=char::MAX as u32)
        .filter_map(char::from_u32)
        .filter(|c| c.to_lowercase().count() > 1)
        .collect();
    assert_eq!(several, vec!['\u{130}']);
}

/// Simple mapping, without context: `İ` is `i`, a final `Σ` is `σ`.
#[test]
fn folds_one_code_point_to_one() {
    let fold = |s: &str| s.chars().map(simple_lowercase).collect::<String>();
    assert_eq!(fold("İREM"), "irem");
    assert_eq!(fold("ΟΔΟΣ"), "οδοσ");
    assert_eq!(fold("ÉLODIE"), "élodie");
}
