// SPDX-License-Identifier: AGPL-3.0-only
//! Accept-Language header parsing and locale negotiation.
//!
//! Implements RFC 7231 §5.3.5 — weighted language tag matching
//! with fallback to the first available compiled locale (English).

use crate::available_locales;

/// A parsed language preference from Accept-Language header.
#[derive(Debug, Clone, PartialEq)]
pub struct LanguagePreference {
    /// Language tag (e.g., "en", "de", "fr-CA").
    pub tag: String,
    /// Quality value (0.0–1.0). Default is 1.0.
    pub quality: f32,
}

/// Parse an Accept-Language header value into sorted preferences.
///
/// # Examples
///
/// ```rust
/// use sid_i18n::parse_accept_language;
///
/// let prefs = parse_accept_language("de, en-US;q=0.8, fr;q=0.5");
/// assert_eq!(prefs[0].tag, "de");
/// assert_eq!(prefs[1].tag, "en-us");
/// assert_eq!(prefs[2].tag, "fr");
/// ```
pub fn parse_accept_language(header: &str) -> Vec<LanguagePreference> {
    let mut prefs: Vec<LanguagePreference> = header
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }

            let mut sections = part.split(';');
            let tag = sections.next()?.trim().to_lowercase();

            let quality = sections
                .find_map(|s| {
                    let s = s.trim();
                    if let Some(q) = s.strip_prefix("q=") {
                        q.parse::<f32>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(1.0)
                .clamp(0.0, 1.0);

            Some(LanguagePreference { tag, quality })
        })
        .collect();

    // Sort by quality descending (stable sort preserves order for equal quality)
    prefs.sort_by(|a, b| {
        b.quality
            .partial_cmp(&a.quality)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    prefs
}

/// Negotiate the best locale from an Accept-Language header.
///
/// Matches against compiled locales using these rules:
/// 1. Exact match (e.g., "de" matches "de")
/// 2. Base language match (e.g., "de-AT" matches "de")
/// 3. Falls back to "en" if no match found
///
/// # Examples
///
/// ```rust
/// use sid_i18n::negotiate_locale;
///
/// // Direct match
/// assert_eq!(negotiate_locale("en"), "en");
///
/// // Base language match (en-US → en)
/// assert_eq!(negotiate_locale("en-US"), "en");
///
/// // Fallback when no match
/// assert_eq!(negotiate_locale("xx-YY"), "en");
/// ```
pub fn negotiate_locale(accept_language: &str) -> &'static str {
    let prefs = parse_accept_language(accept_language);
    let available = available_locales();

    for pref in &prefs {
        // Skip wildcard
        if pref.tag == "*" {
            continue;
        }

        // Exact match
        if available.contains(&pref.tag.as_str()) {
            // Find the static reference
            for &loc in available {
                if loc == pref.tag {
                    return loc;
                }
            }
        }

        // Base language match (e.g., "en-us" → "en")
        if let Some(base) = pref.tag.split('-').next() {
            for &loc in available {
                if loc == base {
                    return loc;
                }
            }
        }
    }

    // Default fallback
    "en"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let prefs = parse_accept_language("en");
        assert_eq!(prefs.len(), 1);
        assert_eq!(prefs[0].tag, "en");
        assert_eq!(prefs[0].quality, 1.0);
    }

    #[test]
    fn test_parse_multiple_with_quality() {
        let prefs = parse_accept_language("de, en;q=0.8, fr;q=0.5");
        assert_eq!(prefs.len(), 3);
        assert_eq!(prefs[0].tag, "de");
        assert_eq!(prefs[0].quality, 1.0);
        assert_eq!(prefs[1].tag, "en");
        assert_eq!(prefs[1].quality, 0.8);
        assert_eq!(prefs[2].tag, "fr");
        assert_eq!(prefs[2].quality, 0.5);
    }

    #[test]
    fn test_parse_with_region() {
        let prefs = parse_accept_language("en-US, en;q=0.9");
        assert_eq!(prefs[0].tag, "en-us");
        assert_eq!(prefs[1].tag, "en");
    }

    #[test]
    fn test_parse_empty() {
        let prefs = parse_accept_language("");
        assert!(prefs.is_empty());
    }

    #[test]
    fn test_parse_whitespace() {
        let prefs = parse_accept_language("  en ,  de ; q=0.5  ");
        assert_eq!(prefs.len(), 2);
        assert_eq!(prefs[0].tag, "en");
        assert_eq!(prefs[1].tag, "de");
    }

    #[test]
    fn test_parse_quality_clamped() {
        let prefs = parse_accept_language("en;q=1.5, de;q=-0.5");
        assert_eq!(prefs[0].quality, 1.0);
        assert_eq!(prefs[1].quality, 0.0);
    }

    #[test]
    fn test_negotiate_exact_match() {
        assert_eq!(negotiate_locale("en"), "en");
    }

    #[test]
    fn test_negotiate_region_fallback() {
        // en-US → en (base language match)
        assert_eq!(negotiate_locale("en-US"), "en");
    }

    #[test]
    fn test_negotiate_unknown_fallback() {
        assert_eq!(negotiate_locale("xx-YY"), "en");
    }

    #[test]
    fn test_negotiate_empty() {
        assert_eq!(negotiate_locale(""), "en");
    }

    #[test]
    fn test_negotiate_wildcard_skipped() {
        // Wildcard alone should fall back to en
        assert_eq!(negotiate_locale("*"), "en");
    }

    #[test]
    fn test_negotiate_quality_order() {
        // Even though de comes first, en has higher quality
        let locale = negotiate_locale("de;q=0.5, en;q=0.9");
        assert_eq!(locale, "en");
    }

    #[test]
    fn test_negotiate_first_available_wins() {
        // Both have quality 1.0, de listed first
        // But only en is available (without i18n-de feature)
        #[cfg(not(feature = "i18n-de"))]
        {
            let locale = negotiate_locale("de, en");
            assert_eq!(locale, "en");
        }
    }
}
