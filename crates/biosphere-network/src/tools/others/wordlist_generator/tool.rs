use crate::core::{Result, ToolError};
use super::config::{WordlistConfig, WordlistResult};

pub struct WordlistGeneratorTool;

impl WordlistGeneratorTool {
    pub fn generate(config: &WordlistConfig) -> Result<WordlistResult> {
        if config.base_words.is_empty() {
            return Err(ToolError::ExecutionError("No base words provided".to_string()));
        }

        if config.min_length > config.max_length {
            return Err(ToolError::ExecutionError("Min length cannot be greater than max length".to_string()));
        }

        let mut words = std::collections::HashSet::new();

        for base in &config.base_words {
            let base_lower = base.to_lowercase();
            let base_cap = capitalize(&base_lower);

            words.insert(base_lower.clone());
            words.insert(base.clone());
            words.insert(base_cap.clone());
            words.insert(base.to_uppercase());

            if config.use_capitalization {
                words.insert(capitalize(&base_lower));
                words.insert(base_lower.clone());
                words.insert(base.to_uppercase());
                for variant in capitalize_variants(&base_lower) {
                    words.insert(variant);
                }
            }

            if config.use_leet {
                for leet in leet_variants(&base_lower, &config.leet_map) {
                    words.insert(leet);
                }
                for leet in leet_variants(&base_cap, &config.leet_map) {
                    words.insert(leet);
                }
            }

            if config.use_reverse {
                words.insert(reverse(&base_lower));
                words.insert(reverse(&base_cap));
            }

            if config.use_append_numbers {
                for num in &config.custom_numbers {
                    words.insert(format!("{}{}", base_lower, num));
                    words.insert(format!("{}{}", base_cap, num));
                    words.insert(format!("{}{}", num, base_lower));
                    words.insert(format!("{}_{}", base_lower, num));
                }
            }

            if config.use_append_symbols {
                for sym in &config.custom_symbols {
                    words.insert(format!("{}{}", base_lower, sym));
                    words.insert(format!("{}{}", base_cap, sym));
                    words.insert(format!("{}{}", sym, base_lower));
                    words.insert(format!("{}_{}", base_lower, sym));
                }
            }

            if config.use_year_suffix {
                let current_year = 2026;
                for year in (current_year - 15)..=(current_year + 1) {
                    words.insert(format!("{}{}", base_lower, year));
                    words.insert(format!("{}{}", base_cap, year));
                    words.insert(format!("{}{}", year, base_lower));
                    words.insert(format!("{}_{}", base_lower, year));
                }
            }
        }

        if config.use_combination && config.base_words.len() >= 2 {
            for i in 0..config.base_words.len() {
                for j in 0..config.base_words.len() {
                    if i != j {
                        let a = config.base_words[i].to_lowercase();
                        let b = config.base_words[j].to_lowercase();
                        words.insert(format!("{}{}", a, b));
                        words.insert(format!("{}{}", capitalize(&a), capitalize(&b)));
                        words.insert(format!("{}_{}", a, b));
                        words.insert(format!("{}-{}", a, b));
                        words.insert(format!("{}.{}", a, b));
                        words.insert(format!("{}@{}", a, b));
                        words.insert(format!("{}#{}", a, b));
                    }
                }
            }
        }

        let mut result: Vec<String> = words.into_iter()
            .filter(|w| w.len() >= config.min_length && w.len() <= config.max_length)
            .collect();

        result.sort();
        result.dedup();

        let total_count = result.len();
        let config_summary = format!(
            "configSummary|baseWords={}|minLength={}|maxLength={}|leet={}|caps={}|numbers={}|symbols={}|years={}|reverse={}|combo={}",
            config.base_words.len(),
            config.min_length,
            config.max_length,
            config.use_leet,
            config.use_capitalization,
            config.use_append_numbers,
            config.use_append_symbols,
            config.use_year_suffix,
            config.use_reverse,
            config.use_combination,
        );

        Ok(WordlistResult {
            total_count,
            words: result,
            config_summary,
        })
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn capitalize_variants(s: &str) -> Vec<String> {
    let mut variants = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return variants;
    }

    variants.push(s.to_uppercase());
    variants.push(s.to_lowercase());
    variants.push(capitalize(s));

    if chars.len() >= 2 {
        let mut alt = String::new();
        for (i, &c) in chars.iter().enumerate() {
            if i % 2 == 0 {
                alt.push(c.to_ascii_uppercase());
            } else {
                alt.push(c.to_ascii_lowercase());
            }
        }
        variants.push(alt);

        let mut alt2 = String::new();
        for (i, &c) in chars.iter().enumerate() {
            if i % 2 == 1 {
                alt2.push(c.to_ascii_uppercase());
            } else {
                alt2.push(c.to_ascii_lowercase());
            }
        }
        variants.push(alt2);
    }

    variants
}

fn leet_variants(word: &str, leet_map: &std::collections::HashMap<String, Vec<String>>) -> Vec<String> {
    let mut results = vec![String::new()];

    for c in word.chars() {
        let lower = c.to_ascii_lowercase();
        let key = lower.to_string();
        if let Some(replacements) = leet_map.get(&key) {
            let mut new_results = Vec::new();
            for existing in &results {
                new_results.push(format!("{}{}", existing, c));
                for rep in replacements {
                    new_results.push(format!("{}{}", existing, rep));
                }
            }
            results = new_results;
        } else {
            for r in &mut results {
                r.push(c);
            }
        }

        if results.len() > 500 {
            results.truncate(500);
            break;
        }
    }

    results
}

fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}
