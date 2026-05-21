use crate::core::{Tool, ToolInfo, ToolArgs, ToolOutput, ToolCategory, Result, ProgressReporter, ToolError};
use rand::Rng;
use serde::{Deserialize, Serialize};
use super::{PasswordConfig, PasswordResult};

pub struct PasswordGenerator;

impl Default for PasswordGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordGenerator {
    pub fn new() -> Self {
        Self
    }

    fn build_charset(&self, config: &PasswordConfig) -> String {
        let mut charset = String::new();

        if config.include_lowercase {
            if config.exclude_similar {
                charset.push_str("abcdefghijkmnopqrstuvwxyz");
            } else {
                charset.push_str("abcdefghijklmnopqrstuvwxyz");
            }
        }

        if config.include_uppercase {
            if config.exclude_similar {
                charset.push_str("ABCDEFGHJKLMNPQRSTUVWXYZ");
            } else {
                charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            }
        }

        if config.include_numbers {
            if config.exclude_similar || config.exclude_ambiguous {
                charset.push_str("23456789");
            } else {
                charset.push_str("0123456789");
            }
        }

        if config.include_symbols {
            if config.exclude_ambiguous {
                charset.push_str("!@#$%^&*+-=?");
            } else {
                charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
            }
        }

        charset
    }

    fn generate_single(&self, length: u32, charset: &str) -> Result<String> {
        if charset.is_empty() {
            return Err(ToolError::ExecutionError("At least one character type must be selected".to_string()));
        }

        if length == 0 || length > 2048 {
            return Err(ToolError::ExecutionError(format!("Invalid password length: {}. Must be between 1 and 2048", length)));
        }

        let mut rng = rand::thread_rng();
        let password: String = (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset.chars().nth(idx).unwrap()
            })
            .collect();

        Ok(password)
    }

    pub fn generate(&self, config: PasswordConfig) -> Result<PasswordResult> {
        let charset = self.build_charset(&config);

        if charset.is_empty() {
            return Ok(PasswordResult::error(
                "At least one character type must be selected".to_string()
            ));
        }

        let mut passwords = Vec::new();

        for _ in 0..config.count {
            match self.generate_single(config.length, &charset) {
                Ok(password) => passwords.push(password),
                Err(e) => return Ok(PasswordResult::error(e.to_string())),
            }
        }

        Ok(PasswordResult::success(passwords, config))
    }

    pub fn generate_passphrase(&self, word_count: u32, separator: &str) -> Result<String> {
        const WORD_LIST: &[&str] = &[
            "apple", "banana", "cherry", "dragon", "elephant",
            "forest", "garden", "harbor", "island", "jungle",
            "knight", "lemon", "mountain", "night", "ocean",
            "palace", "queen", "river", "sunset", "tiger",
            "umbrella", "violet", "wizard", "yellow", "zebra",
            "adventure", "balance", "crystal", "diamond", "eagle",
            "falcon", "galaxy", "harmony", "infinity", "journey",
            "anchor", "breeze", "canyon", "dewdrop", "ember",
            "frost", "glacier", "horizon", "ivory", "jade",
            "kaleidoscope", "lighthouse", "meadow", "nebula", "oracle",
            "prism", "quartz", "rainbow", "sapphire", "thunder",
            "unicorn", "velocity", "whisper", "xenon", "yesterday",
            "zenith", "aurora", "blizzard", "cascade", "dawn",
            "eclipse", "flame", "granite", "honey", "impulse",
            "jewel", "karma", "lunar", "magnet", "nova",
            "oasis", "phoenix", "quill", "rhythm", "storm",
            "tropic", "utopia", "vortex", "wonder", "xenith",
            "yearn", "zephyr", "amber", "birch", "coral",
            "dusk", "fir", "glen", "haze", "iris",
            "juniper", "kite", "lark", "mist", "nook",
            "opal", "pine", "reef", "sage", "twilight",
            "vale", "wave", "bloom", "creek", "dell",
            "fern", "grove", "hill", "lake", "moss",
            "pond", "ridge", "shore", "trail", "wood",
            "copper", "silver", "bronze", "platinum", "cobalt",
            "crimson", "scarlet", "indigo", "maroon", "teal",
            "cipher", "enigma", "puzzle", "riddle", "secret",
            "shadow", "stealth", "phantom", "ghost", "spirit",
            "rocket", "comet", "meteor", "stellar", "cosmic",
            "neutron", "proton", "quantum", "photon", "fusion",
            "titan", "atlas", "hercules", "odin", "thor",
            "mercury", "venus", "mars", "jupiter", "saturn",
            "neptune", "pluto", "orion", "lyra", "vega",
            "arctic", "tropic", "equator", "polar", "thermal",
            "sonic", "radar", "laser", "pulse", "spark",
            "nexus", "matrix", "vector", "scalar", "tensor",
            "alpha", "beta", "gamma", "delta", "omega",
            "sigma", "theta", "lambda", "zeta", "kappa",
            "bridge", "tower", "castle", "fortress", "haven",
            "sanctum", "temple", "chapel", "shrine", "altar",
            "compass", "anchor", "rudder", "helm", "mast",
            "canvas", "palette", "mosaic", "fresco", "mural",
            "rhythm", "melody", "harmony", "chorus", "echo",
            "fable", "legend", "myth", "saga", "epic",
            "script", "scroll", "tome", "folio", "codex",
        ];

        if word_count == 0 || word_count > 20 {
            return Err(ToolError::ExecutionError("Word count must be between 1 and 20".to_string()));
        }

        let mut rng = rand::thread_rng();
        let words: Vec<String> = (0..word_count)
            .map(|_| {
                let idx = rng.gen_range(0..WORD_LIST.len());
                WORD_LIST[idx].to_string()
            })
            .collect();

        Ok(words.join(separator))
    }

    pub fn check_strength(password: &str) -> PasswordStrength {
        let mut score = 0u32;
        let mut feedback = Vec::new();

        if password.len() >= 8 {
            score += 1;
        } else {
            feedback.push("feedback.minLength8".to_string());
        }

        if password.len() >= 12 {
            score += 1;
        }

        if password.len() >= 16 {
            score += 1;
        }

        if password.len() >= 24 {
            score += 1;
        }

        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        } else {
            feedback.push("feedback.includeLowercase".to_string());
        }

        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        } else {
            feedback.push("feedback.includeUppercase".to_string());
        }

        if password.chars().any(|c| c.is_numeric()) {
            score += 1;
        } else {
            feedback.push("feedback.includeNumbers".to_string());
        }

        if password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) {
            score += 1;
        } else {
            feedback.push("feedback.includeSymbols".to_string());
        }

        let has_repeated = {
            let chars: Vec<char> = password.chars().collect();
            let mut found = false;
            for i in 0..chars.len().saturating_sub(2) {
                if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
                    found = true;
                    break;
                }
            }
            found
        };
        if has_repeated {
            score = score.saturating_sub(1);
            feedback.push("feedback.repeatedChars".to_string());
        }

        let is_sequential = {
            let chars: Vec<char> = password.chars().collect();
            let mut found = false;
            for i in 0..chars.len().saturating_sub(2) {
                if let (Some(a), Some(b), Some(c)) = (chars[i].to_digit(36), chars[i+1].to_digit(36), chars[i+2].to_digit(36)) {
                    if (a + 1 == b && b + 1 == c) || (a == b + 1 && b == c + 1) {
                        found = true;
                        break;
                    }
                }
            }
            found
        };
        if is_sequential {
            score = score.saturating_sub(1);
            feedback.push("feedback.sequentialChars".to_string());
        }

        const COMMON_PASSWORDS: &[&str] = &[
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "master", "dragon", "login", "princess",
            "football", "shadow", "sunshine", "trustno1", "iloveyou",
            "batman", "access", "hello", "charlie", "donald",
            "password1", "qwerty123", "letmein", "welcome", "admin",
        ];
        let lower = password.to_lowercase();
        if COMMON_PASSWORDS.contains(&lower.as_str()) {
            score = score.saturating_sub(2);
            feedback.push("feedback.commonPassword".to_string());
        }

        let level = match score {
            0..=2 => StrengthLevel::Weak,
            3..=5 => StrengthLevel::Medium,
            6..=7 => StrengthLevel::Strong,
            _ => StrengthLevel::VeryStrong,
        };

        PasswordStrength {
            score,
            max_score: 10,
            level,
            feedback,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub score: u32,
    pub max_score: u32,
    pub level: StrengthLevel,
    pub feedback: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrengthLevel {
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl std::fmt::Display for StrengthLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrengthLevel::Weak => write!(f, "Weak"),
            StrengthLevel::Medium => write!(f, "Medium"),
            StrengthLevel::Strong => write!(f, "Strong"),
            StrengthLevel::VeryStrong => write!(f, "VeryStrong"),
        }
    }
}

impl Tool for PasswordGenerator {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            id: "password_generator".to_string(),
            name: "Password Generator".to_string(),
            description: "Generate strong random passwords with customizable options".to_string(),
            category: ToolCategory::Other,
            installed: true,
        }
    }

    fn run(&self, args: ToolArgs, _progress: Option<Box<dyn ProgressReporter>>) -> Result<ToolOutput> {
        let config_json = args.get_target()?;
        let config: PasswordConfig = serde_json::from_str(config_json)
            .map_err(|e| ToolError::ExecutionError(format!("Invalid config: {}", e)))?;

        let result = self.generate(config)?;

        let json = serde_json::to_string(&result)
            .map_err(|e| ToolError::ExecutionError(e.to_string()))?;

        Ok(ToolOutput::success(json))
    }
}

pub fn generate_passwords(config: PasswordConfig) -> Result<PasswordResult> {
    PasswordGenerator::new().generate(config)
}

pub fn generate_passphrase(word_count: u32, separator: String) -> Result<String> {
    PasswordGenerator::new().generate_passphrase(word_count, &separator)
}

pub fn check_password_strength(password: String) -> PasswordStrength {
    PasswordGenerator::check_strength(&password)
}
