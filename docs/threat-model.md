# Threat Model

## What MCPRadar Detects

### 1. Tool Poisoning (Supply Chain)
**Vector:** Bir MCP server geliştiricisi, zararlı tool tanımları yayınlar.
- R001: `eval`, `exec`, `rm` gibi tehlikeli isimler
- R105: Tool isminin ima ettiğinden farklı yetkiler

### 2. Prompt Injection via Tool Metadata
**Vector:** Tool description/schema'sına LLM'i manipüle edecek pattern'ler 
gizlenir.
- R102: 10 prompt injection pattern'i
- R103: Base64/hex ile gizlenmiş injection
- R104: HTML/Markdown ile gizlenmiş injection

### 3. Hidden Text Attacks
**Vector:** Unicode trick'leriyle tool ismi veya description'ı değiştirme.
- R101: Zero-width karakterler, BOM, directional override

## What MCPRadar Does NOT Detect

### Runtime Exploits
MCPRadar **static analysis** yapar — tool tanımını inceler, çalışma zamanı 
davranışını değil. Şunları yakalayamaz:
- Tool'un gerçek implementasyonundaki buffer overflow
- API key'lerin loglanması
- Network trafiğinin sniff edilmesi

### Server Infrastructure
- MCP server'ın kendisinin CVE'leri
- Transport-level güvenlik (TLS, auth bypass)
- Resource exhaustion / DoS

### Behavioral Anomalies
- Tool'un çağrılma sıklığındaki anormallikler
- Beklenmedik tool kombinasyonları (cross-tool attack)
- Kullanıcı input'larının tool'lara geçiş pattern'leri

## Attack Surface

```
[User] → [LLM Client] → [MCP Protocol] → [MCP Server] → [Tool Implementation]
                                                  ↑
                                          MCPRadar scans here
                                     (tool definitions only)
```

## Severity Classification

| Severity | Meaning | Example |
|---|---|---|
| CRITICAL | Direct LLM manipulation, remote code execution risk | Prompt injection in description |
| HIGH | Hidden attack vector, requires user interaction | ZWSP in tool name |
| MEDIUM | Suspicious pattern, needs investigation | Base64 blob without clear payload |
| LOW | Informational, likely benign | Scope mismatch with bridge context |

## Responsible Disclosure

Eğer MCPRadar ile gerçek bir güvenlik açığı bulursanız:
1. Etkilenen MCP server'ın maintainer'ına 30 gün verin
2. CVE talep edin
3. MCPRadar'ın [SECURITY.md](../SECURITY.md) dosyasındaki adımları izleyin

MCPRadar'ın kendisinde bir güvenlik açığı bulursanız: 
`security@` adresine veya GPG anahtarıyla bildirin.
