use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdnCheckConfig {
    pub domain: String,
    pub generate_variants: bool,
    pub check_dns: bool,
    pub check_brand: bool,
    pub max_variants: usize,
}

impl Default for IdnCheckConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            generate_variants: true,
            check_dns: true,
            check_brand: true,
            max_variants: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdnCheckResult {
    pub original_domain: String,
    pub punycode_domain: Option<String>,
    pub is_idn: bool,
    pub is_suspicious: bool,
    pub risk_level: String,
    pub risk_score: f64,
    pub suspicious_chars: Vec<SuspiciousChar>,
    pub similar_domains: Vec<SimilarDomain>,
    pub generated_variants: Vec<DomainVariant>,
    pub script_analysis: ScriptAnalysis,
    pub brand_match: Option<BrandMatch>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousChar {
    pub position: usize,
    pub char: String,
    pub unicode_codepoint: String,
    pub unicode_name: String,
    pub resembles: String,
    pub category: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarDomain {
    pub domain: String,
    pub similarity_type: String,
    pub punycode: Option<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVariant {
    pub domain: String,
    pub punycode: String,
    pub variant_type: String,
    pub substitutions: Vec<CharSubstitution>,
    pub is_registered: Option<bool>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharSubstitution {
    pub original: String,
    pub replaced: String,
    pub position: usize,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptAnalysis {
    pub scripts: Vec<ScriptInfo>,
    pub is_mixed_script: bool,
    pub is_single_script: bool,
    pub has_confusable: bool,
    pub script_count: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub script: String,
    pub char_count: usize,
    pub has_confusable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandMatch {
    pub brand: String,
    pub category: String,
    pub confidence: f64,
    pub matched_positions: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchIdnCheckResult {
    pub total: usize,
    pub suspicious_count: usize,
    pub safe_count: usize,
    pub error_count: usize,
    pub results: Vec<IdnCheckResult>,
    pub summary: String,
}

pub const CONFUSABLE_CHARS: &[(char, char, &str, &str)] = &[
    ('а', 'a', "Cyrillic", "CYRILLIC SMALL LETTER A"),
    ('е', 'e', "Cyrillic", "CYRILLIC SMALL LETTER IE"),
    ('о', 'o', "Cyrillic", "CYRILLIC SMALL LETTER O"),
    ('р', 'p', "Cyrillic", "CYRILLIC SMALL LETTER ER"),
    ('с', 'c', "Cyrillic", "CYRILLIC SMALL LETTER ES"),
    ('у', 'y', "Cyrillic", "CYRILLIC SMALL LETTER U"),
    ('х', 'x', "Cyrillic", "CYRILLIC SMALL LETTER HA"),
    ('і', 'i', "Cyrillic", "CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I"),
    ('ј', 'j', "Cyrillic", "CYRILLIC SMALL LETTER JE"),
    ('ѕ', 's', "Cyrillic", "CYRILLIC SMALL LETTER DZE"),
    ('ԁ', 'd', "Cyrillic", "CYRILLIC SMALL LETTER KOMI DE"),
    ('Ԍ', 'G', "Cyrillic", "CYRILLIC CAPITAL LETTER KOMI ES"),
    ('А', 'A', "Cyrillic", "CYRILLIC CAPITAL LETTER A"),
    ('В', 'B', "Cyrillic", "CYRILLIC CAPITAL LETTER VE"),
    ('Е', 'E', "Cyrillic", "CYRILLIC CAPITAL LETTER IE"),
    ('К', 'K', "Cyrillic", "CYRILLIC CAPITAL LETTER KA"),
    ('М', 'M', "Cyrillic", "CYRILLIC CAPITAL LETTER EM"),
    ('Н', 'H', "Cyrillic", "CYRILLIC CAPITAL LETTER EN"),
    ('О', 'O', "Cyrillic", "CYRILLIC CAPITAL LETTER O"),
    ('Р', 'P', "Cyrillic", "CYRILLIC CAPITAL LETTER ER"),
    ('С', 'C', "Cyrillic", "CYRILLIC CAPITAL LETTER ES"),
    ('Т', 'T', "Cyrillic", "CYRILLIC CAPITAL LETTER TE"),
    ('У', 'Y', "Cyrillic", "CYRILLIC CAPITAL LETTER U"),
    ('Х', 'X', "Cyrillic", "CYRILLIC CAPITAL LETTER HA"),
    ('ⲁ', 'a', "Coptic", "COPTIC SMALL LETTER ALPHA"),
    ('ⲉ', 'e', "Coptic", "COPTIC SMALL LETTER EI"),
    ('ⲟ', 'o', "Coptic", "COPTIC SMALL LETTER O"),
    ('ⲡ', 'p', "Coptic", "COPTIC SMALL LETTER PI"),
    ('ⲥ', 's', "Coptic", "COPTIC SMALL LETTER SIMA"),
    ('ⲩ', 'y', "Coptic", "COPTIC SMALL LETTER UDA"),
    ('ⲕ', 'k', "Coptic", "COPTIC SMALL LETTER KAPA"),
    ('ⲛ', 'n', "Coptic", "COPTIC SMALL LETTER NI"),
    ('ⲣ', 'r', "Coptic", "COPTIC SMALL LETTER RO"),
    ('ⲧ', 't', "Coptic", "COPTIC SMALL LETTER TAU"),
    ('ɡ', 'g', "Latin Extended", "LATIN SMALL LETTER SCRIPT G"),
    ('ɪ', 'I', "Latin Extended", "LATIN LETTER SMALL CAPITAL I"),
    ('ʟ', 'L', "Latin Extended", "LATIN LETTER SMALL CAPITAL L"),
    ('ꜱ', 'S', "Latin Extended", "LATIN LETTER SMALL CAPITAL S"),
    ('ᴛ', 'T', "Latin Extended", "LATIN LETTER SMALL CAPITAL T"),
    ('Ɒ', 'O', "Latin Extended", "LATIN LETTER SMALL CAPITAL OU"),
    ('ǀ', 'l', "Latin Extended", "LATIN LETTER DENTAL CLICK"),
    ('Ⓐ', 'A', "Enclosed", "CIRCLED LATIN CAPITAL LETTER A"),
    ('Ⓑ', 'B', "Enclosed", "CIRCLED LATIN CAPITAL LETTER B"),
    ('Ⓒ', 'C', "Enclosed", "CIRCLED LATIN CAPITAL LETTER C"),
    ('α', 'a', "Greek", "GREEK SMALL LETTER ALPHA"),
    ('ε', 'e', "Greek", "GREEK SMALL LETTER EPSILON"),
    ('ο', 'o', "Greek", "GREEK SMALL LETTER OMICRON"),
    ('κ', 'k', "Greek", "GREEK SMALL LETTER KAPPA"),
    ('ν', 'v', "Greek", "GREEK SMALL LETTER NU"),
    ('ρ', 'p', "Greek", "GREEK SMALL LETTER RHO"),
    ('τ', 't', "Greek", "GREEK SMALL LETTER TAU"),
    ('υ', 'u', "Greek", "GREEK SMALL LETTER UPSILON"),
    ('χ', 'x', "Greek", "GREEK SMALL LETTER CHI"),
    ('Α', 'A', "Greek", "GREEK CAPITAL LETTER ALPHA"),
    ('Β', 'B', "Greek", "GREEK CAPITAL LETTER BETA"),
    ('Ε', 'E', "Greek", "GREEK CAPITAL LETTER EPSILON"),
    ('Ζ', 'Z', "Greek", "GREEK CAPITAL LETTER ZETA"),
    ('Η', 'H', "Greek", "GREEK CAPITAL LETTER ETA"),
    ('Ι', 'I', "Greek", "GREEK CAPITAL LETTER IOTA"),
    ('Κ', 'K', "Greek", "GREEK CAPITAL LETTER KAPPA"),
    ('Μ', 'M', "Greek", "GREEK CAPITAL LETTER MU"),
    ('Ν', 'N', "Greek", "GREEK CAPITAL LETTER NU"),
    ('Ο', 'O', "Greek", "GREEK CAPITAL LETTER OMICRON"),
    ('Ρ', 'P', "Greek", "GREEK CAPITAL LETTER RHO"),
    ('Τ', 'T', "Greek", "GREEK CAPITAL LETTER TAU"),
    ('Υ', 'Y', "Greek", "GREEK CAPITAL LETTER UPSILON"),
    ('Χ', 'X', "Greek", "GREEK CAPITAL LETTER CHI"),
    ('հ', 'h', "Armenian", "ARMENIAN SMALL LETTER HO"),
    ('ո', 'n', "Armenian", "ARMENIAN SMALL LETTER VO"),
    ('ս', 's', "Armenian", "ARMENIAN SMALL LETTER SE"),
    ('դ', 'd', "Armenian", "ARMENIAN SMALL LETTER DA"),
    ('գ', 'g', "Armenian", "ARMENIAN SMALL LETTER GIM"),
    ('〇', '0', "CJK", "IDEOGRAPHIC NUMBER ZERO"),
    ('－', '-', "CJK", "FULLWIDTH HYPHEN-MINUS"),
    ('＿', '_', "CJK", "FULLWIDTH LOW LINE"),
    ('．', '.', "CJK", "FULLWIDTH FULL STOP"),
    ('Ꭺ', 'A', "Cherokee", "CHEROKEE LETTER GO"),
    ('Ꭼ', 'E', "Cherokee", "CHEROKEE LETTER GV"),
    ('Ꮋ', 'H', "Cherokee", "CHEROKEE LETTER HI"),
    ('Ꮇ', 'M', "Cherokee", "CHEROKEE LETTER LU"),
    ('Ꮮ', 'L', "Cherokee", "CHEROKEE LETTER TLE"),
    ('Ꮲ', 'P', "Cherokee", "CHEROKEE LETTER TSE"),
    ('Ꮶ', 'Z', "Cherokee", "CHEROKEE LETTER TSO"),
];

pub const BRAND_DOMAINS: &[(&str, &str)] = &[
    ("paypal", "Payment"),
    ("google", "Technology"),
    ("apple", "Technology"),
    ("microsoft", "Technology"),
    ("amazon", "E-Commerce"),
    ("facebook", "Social Media"),
    ("instagram", "Social Media"),
    ("twitter", "Social Media"),
    ("x.com", "Social Media"),
    ("linkedin", "Social Media"),
    ("netflix", "Entertainment"),
    ("spotify", "Entertainment"),
    ("github", "Technology"),
    ("gitlab", "Technology"),
    ("dropbox", "Cloud Storage"),
    ("slack", "Communication"),
    ("discord", "Communication"),
    ("telegram", "Communication"),
    ("whatsapp", "Communication"),
    ("wechat", "Communication"),
    ("alipay", "Payment"),
    ("taobao", "E-Commerce"),
    ("jd", "E-Commerce"),
    ("baidu", "Technology"),
    ("tencent", "Technology"),
    ("bytedance", "Technology"),
    ("douyin", "Entertainment"),
    ("tiktok", "Entertainment"),
    ("alibaba", "E-Commerce"),
    ("cloudflare", "Technology"),
    ("stripe", "Payment"),
    ("binance", "Cryptocurrency"),
    ("coinbase", "Cryptocurrency"),
    ("openai", "AI"),
    ("chatgpt", "AI"),
    ("youtube", "Entertainment"),
    ("gmail", "Email"),
    ("outlook", "Email"),
    ("yahoo", "Technology"),
    ("samsung", "Technology"),
    ("huawei", "Technology"),
    ("xiaomi", "Technology"),
];
