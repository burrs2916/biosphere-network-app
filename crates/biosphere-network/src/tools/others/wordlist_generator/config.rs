use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistConfig {
    pub base_words: Vec<String>,
    pub min_length: usize,
    pub max_length: usize,
    pub use_leet: bool,
    pub use_capitalization: bool,
    pub use_append_numbers: bool,
    pub use_append_symbols: bool,
    pub use_year_suffix: bool,
    pub use_reverse: bool,
    pub use_combination: bool,
    pub custom_numbers: Vec<String>,
    pub custom_symbols: Vec<String>,
    pub leet_map: std::collections::HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordlistResult {
    pub total_count: usize,
    pub words: Vec<String>,
    pub config_summary: String,
}

impl Default for WordlistConfig {
    fn default() -> Self {
        let mut leet_map = std::collections::HashMap::new();
        leet_map.insert("a".to_string(), vec!["4".to_string(), "@".to_string()]);
        leet_map.insert("e".to_string(), vec!["3".to_string()]);
        leet_map.insert("i".to_string(), vec!["1".to_string(), "!".to_string()]);
        leet_map.insert("o".to_string(), vec!["0".to_string()]);
        leet_map.insert("s".to_string(), vec!["5".to_string(), "$".to_string()]);
        leet_map.insert("t".to_string(), vec!["7".to_string()]);
        leet_map.insert("l".to_string(), vec!["1".to_string()]);
        leet_map.insert("b".to_string(), vec!["8".to_string()]);
        leet_map.insert("g".to_string(), vec!["9".to_string()]);

        Self {
            base_words: vec![],
            min_length: 4,
            max_length: 32,
            use_leet: true,
            use_capitalization: true,
            use_append_numbers: true,
            use_append_symbols: false,
            use_year_suffix: true,
            use_reverse: true,
            use_combination: true,
            custom_numbers: vec!["0".into(), "1".into(), "12".into(), "123".into(), "1234".into(), "69".into(), "007".into()],
            custom_symbols: vec!["!".into(), "@".into(), "#".into(), "$".into(), "!!".into(), "@@".into()],
            leet_map,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuppConfig {
    pub firstname: String,
    pub middlename: String,
    pub lastname: String,
    pub nickname: String,
    pub birthdate: String,
    pub partner_name: String,
    pub partner_birthdate: String,
    pub child_name: String,
    pub child_birthdate: String,
    pub pet_name: String,
    pub company: String,
    pub street: String,
    pub city: String,
    pub country: String,
    pub hobbies: Vec<String>,
    pub keywords: Vec<String>,
    pub custom_words: Vec<String>,
    pub use_leet: bool,
    pub use_capitalization: bool,
    pub use_reverse: bool,
    pub use_append_numbers: bool,
    pub use_append_symbols: bool,
    pub use_year_suffix: bool,
    pub use_combination: bool,
    pub min_length: usize,
    pub max_length: usize,
}

impl Default for CuppConfig {
    fn default() -> Self {
        Self {
            firstname: String::new(),
            middlename: String::new(),
            lastname: String::new(),
            nickname: String::new(),
            birthdate: String::new(),
            partner_name: String::new(),
            partner_birthdate: String::new(),
            child_name: String::new(),
            child_birthdate: String::new(),
            pet_name: String::new(),
            company: String::new(),
            street: String::new(),
            city: String::new(),
            country: String::new(),
            hobbies: Vec::new(),
            keywords: Vec::new(),
            custom_words: Vec::new(),
            use_leet: true,
            use_capitalization: true,
            use_reverse: true,
            use_append_numbers: true,
            use_append_symbols: true,
            use_year_suffix: true,
            use_combination: true,
            min_length: 4,
            max_length: 32,
        }
    }
}

pub fn generate_cupp_wordlist(config: &CuppConfig) -> Vec<String> {
    let mut words = Vec::new();
    let mut base = Vec::new();

    if !config.firstname.is_empty() {
        base.push(config.firstname.clone());
        base.push(config.firstname.to_lowercase());
        base.push(config.firstname.to_uppercase());
        let first_lower = config.firstname.to_lowercase();
        base.push(format!("{}{}", first_lower.chars().next().unwrap_or('a').to_uppercase(), &first_lower[1..]));
    }
    if !config.middlename.is_empty() {
        base.push(config.middlename.clone());
        base.push(config.middlename.to_lowercase());
        base.push(config.middlename.chars().next().unwrap_or(' ').to_string());
    }
    if !config.lastname.is_empty() {
        base.push(config.lastname.clone());
        base.push(config.lastname.to_lowercase());
        base.push(config.lastname.to_uppercase());
        let last_lower = config.lastname.to_lowercase();
        base.push(format!("{}{}", last_lower.chars().next().unwrap_or('a').to_uppercase(), &last_lower[1..]));
    }
    if !config.nickname.is_empty() {
        base.push(config.nickname.clone());
        base.push(config.nickname.to_lowercase());
    }
    if !config.partner_name.is_empty() {
        base.push(config.partner_name.clone());
        base.push(config.partner_name.to_lowercase());
        base.push(config.partner_name.chars().next().unwrap_or(' ').to_string());
    }
    if !config.child_name.is_empty() {
        base.push(config.child_name.clone());
        base.push(config.child_name.to_lowercase());
    }
    if !config.pet_name.is_empty() {
        base.push(config.pet_name.clone());
        base.push(config.pet_name.to_lowercase());
    }
    if !config.company.is_empty() {
        base.push(config.company.clone());
        base.push(config.company.to_lowercase());
        base.push(config.company.replace(' ', ""));
    }
    if !config.street.is_empty() {
        base.push(config.street.clone());
        base.push(config.street.to_lowercase());
        base.push(config.street.replace(' ', ""));
    }
    if !config.city.is_empty() {
        base.push(config.city.clone());
        base.push(config.city.to_lowercase());
    }
    if !config.country.is_empty() {
        base.push(config.country.clone());
        base.push(config.country.to_lowercase());
    }

    for hobby in &config.hobbies {
        base.push(hobby.clone());
        base.push(hobby.to_lowercase());
        base.push(hobby.replace(' ', ""));
    }
    for keyword in &config.keywords {
        base.push(keyword.clone());
        base.push(keyword.to_lowercase());
    }
    for custom in &config.custom_words {
        base.push(custom.clone());
    }

    let mut date_parts = Vec::new();
    for date_str in &[&config.birthdate, &config.partner_birthdate, &config.child_birthdate] {
        if !date_str.is_empty() {
            let parts: Vec<&str> = date_str.split(|c: char| !c.is_ascii_digit()).filter(|p| !p.is_empty()).collect();
            for part in &parts {
                date_parts.push((*part).to_string());
            }
            if parts.len() >= 3 {
                date_parts.push(format!("{}{}", parts[0], parts[1]));
                date_parts.push(format!("{}{}{}", parts[0], parts[1], parts[2]));
                if parts[2].len() >= 2 {
                    date_parts.push(parts[2][2..].to_string());
                }
            }
        }
    }

    base.extend(date_parts.clone());

    let current_year = 2026;
    if config.use_year_suffix {
        for year in (current_year - 50)..=current_year {
            date_parts.push(year.to_string());
            date_parts.push(format!("{}", year % 100));
        }
    }

    let numbers: Vec<String> = vec![
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "00", "01", "10", "11", "12", "13", "21", "22", "23", "42", "69", "99",
        "100", "123", "1234", "12345", "123456", "007", "777", "888", "999",
    ].iter().map(|s| s.to_string()).collect();

    let symbols: Vec<String> = ["!", "@", "#", "$", "%", "!!", "@@", "!!1", "!@#"].iter().map(|s| s.to_string()).collect();

    let leet_map: std::collections::HashMap<char, Vec<char>> = {
        let mut m = std::collections::HashMap::new();
        m.insert('a', vec!['4', '@']);
        m.insert('e', vec!['3']);
        m.insert('i', vec!['1', '!']);
        m.insert('o', vec!['0']);
        m.insert('s', vec!['5', '$']);
        m.insert('t', vec!['7']);
        m.insert('l', vec!['1']);
        m.insert('b', vec!['8']);
        m.insert('g', vec!['9']);
        m
    };

    words.extend(base.iter().cloned());

    if config.use_combination {
        let name_parts: Vec<&String> = base.iter().take(20).collect();
        for i in 0..name_parts.len().min(10) {
            for j in 0..name_parts.len().min(10) {
                if i != j {
                    words.push(format!("{}{}", name_parts[i], name_parts[j]));
                }
            }
        }
    }

    if config.use_append_numbers {
        for word in base.iter().take(30) {
            for num in &numbers {
                words.push(format!("{}{}", word, num));
                words.push(format!("{}_{}", word, num));
            }
        }
        for date in &date_parts {
            for word in base.iter().take(10) {
                words.push(format!("{}{}", word, date));
                words.push(format!("{}_{}", word, date));
            }
        }
    }

    if config.use_append_symbols {
        for word in base.iter().take(20) {
            for sym in &symbols {
                words.push(format!("{}{}", word, sym));
                words.push(format!("{}{}{}", word, sym, "1"));
            }
        }
    }

    if config.use_reverse {
        let original_count = words.len();
        for i in 0..original_count.min(500) {
            let reversed: String = words[i].chars().rev().collect();
            if reversed != words[i] {
                words.push(reversed);
            }
        }
    }

    if config.use_leet {
        let original_count = words.len();
        for i in 0..original_count.min(300) {
            let leet = apply_leet(&words[i], &leet_map);
            if leet != words[i] {
                words.push(leet);
            }
        }
    }

    if config.use_capitalization {
        let original_count = words.len();
        let mut to_add = Vec::new();
        for word in words.iter().take(original_count.min(200)) {
            if !word.is_empty() {
                to_add.push(word.to_uppercase());
                let mut chars: Vec<char> = word.chars().collect();
                if !chars.is_empty() {
                    chars[0] = chars[0].to_uppercase().next().unwrap_or(chars[0]);
                    to_add.push(chars.into_iter().collect());
                }
            }
        }
        words.extend(to_add);
    }

    words.retain(|w| w.len() >= config.min_length && w.len() <= config.max_length);
    words.sort();
    words.dedup();

    words
}

fn apply_leet(word: &str, leet_map: &std::collections::HashMap<char, Vec<char>>) -> String {
    let mut result = String::new();
    for c in word.chars() {
        if let Some(replacements) = leet_map.get(&c.to_ascii_lowercase()) {
            if let Some(&replacement) = replacements.first() {
                result.push(replacement);
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }
    result
}
