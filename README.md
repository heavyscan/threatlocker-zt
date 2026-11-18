# 🛡️ ThreatLocker® Zero Trust Endpoint Protection Platform (Open Reconstruction)

![Zero Trust](https://img.shields.io/badge/Zero_Trust-Deny_By_Default-0098d6?style=for-the-badge)
![Production Enforcement](https://img.shields.io/badge/Mode-Production_Lockdown-10b981?style=for-the-badge)
![Platforms](https://img.shields.io/badge/Agents-Linux_%7C_Windows-0b223f?style=for-the-badge)
![I18N](https://img.shields.io/badge/I18N-PT--BR_%7C_EN--US-27b7eb?style=for-the-badge)
![AI Control](https://img.shields.io/badge/AI_Control-Local_&_Cloud_LLM-8b5cf6?style=for-the-badge)

Plataforma completa de **Gerenciamento de Cibersegurança Zero Trust** inspirada na arquitetura **ThreatLocker® Zero Trust Endpoint Protection** (*"Deny-by-default, allow-by-exception"*), com Servidor Central (Control Plane WSGI/Gunicorn), Interface Web 100% Bilíngue (**Português `PT-BR`** e **Inglês `EN-US`**), Agentes Multiplataforma (**Linux** & **Windows PowerShell/Python**) e consultor **Cyber Hero® AI**.

---

## 🖼️ Demonstração Visual (Exemplos)

### 1. Central de Comando Zero Trust & Telemetria em Tempo Real (`PT-BR`)
![Dashboard Zero Trust](docs/images/01_dashboard_overview.png)

### 2. Application Allowlisting com Hash SHA-256 Completo (64 Caracteres) e Cópia em 1 Clique (`EN-US`)
![Application Allowlisting SHA-256](docs/images/02_application_allowlisting_sha256.png)

### 3. Cercamento Digital (Ringfencing™) & Governança de Agentes de IA (`PT-BR`)
![Ringfencing & AI Control](docs/images/03_ringfencing_and_ai_control.png)

---

## 🚀 Principais Módulos Zero Trust

1. **Application Allowlisting & Learning Mode (`SHA-256` Completo + Cópia em 1 Clique)**
   - Inventário automático em tempo real de todos os binários em execução nos endpoints (`/proc/<pid>/exe` no Linux e `Get-Process` + `Authenticode` no Windows).
   - Exibição integral do hash criptográfico **SHA-256 de 64 caracteres** com botão de cópia rápida (`📋 Copiar SHA-256` / `📋 Copy SHA-256`).
   - Bloqueio ativo (**Production Lockdown / `SIGKILL`**) de qualquer executável cujo hash criptográfico SHA-256 ou caminho esteja bloqueado, protegendo a baseline crítica do sistema operacional.
2. **Ringfencing™ (Cercamento Digital de Processos, Arquivos e Rede)**
   - Restringe o que aplicações confiáveis (navegadores, suítes Office, interpretadores `python3`, `node`, `powershell.exe` e containers) podem fazer após iniciarem.
   - Bloqueia ataques *Living-off-the-Land (LOTL)* impedindo que processos confinados criem shells filhos (`/bin/bash`, `/bin/sh`, `cmd.exe`, `nc`) ou leiam credenciais (`/etc/shadow`, `~/.ssh`).
3. **Zero Trust AI Control**
   - Governança dedicada para agentes de IA autônomos (**Ollama**, **Hermes Agent**, **MCP Servers**, **AutoGPT**), restringindo diretórios de workspace permitidos, execução de shell e acesso externo à rede.
4. **Network Control (Host Firewall & Dynamic ZTNA ACLs)**
   - Integração com **UFW / iptables** (Linux) e **Windows Defender Firewall** para fechar portas abertas, bloquear movimentação lateral SMB/RPC (`135, 139, 445`) e portas de Reverse Shell (`4444, 1337, 9001`).
5. **Storage Control**
   - Controle granular sobre dispositivos **USB Mass Storage**, partições críticas (`/boot/efi`), volumes de dados e cofres de chaves SSH contra exfiltração de dados.
6. **Elevation Control (Just-In-Time PAM)**
   - Remoção de privilégios permanentes com fluxo de solicitação, justificativa e aprovação temporária (`sudo` / UAC) por comando e hash SHA-256.
7. **DAC — Defense Against Configurations**
   - Monitoramento contínuo de deriva de configuração (*Configuration Drift*): ASLR do Kernel, Firmware UEFI Secure Boot `dbx`, Fail2Ban, UFW, Ubuntu Pro ESM, Microsoft Defender e isolamento de containers.
8. **Unified Audit & EDR + Host Isolation**
   - Telemetria forense unificada em tempo real e isolamento instantâneo de endpoints comprometidos (**Host Quarantine**).
9. **Cyber Hero® AI Advisor & Interface 100% Bilíngue (`PT-BR` / `EN-US`)**
   - Seletor instantâneo de idioma no topo do painel (`🇧🇷 PT-BR` | `🇺🇸 EN-US`) que traduz integralmente menus, tabelas, políticas, status, logs de auditoria e respostas do consultor **Cyber Hero® AI**.

---

## 🏗️ Arquitetura do Projeto

```text
threatlocker-zt/
├── server/
│   ├── app.py                 # Control Plane API & Motor de Políticas Zero Trust (Flask / Gunicorn)
│   └── static/
│       └── index.html         # Portal Web Responsivo Bilíngue (PT-BR / EN-US) com 11 Módulos
├── agents/
│   ├── linux/
│   │   └── tl_agent_linux.py  # Agente de Produção Linux (SHA-256, Ringfencing SIGKILL, DAC, UFW)
│   └── windows/
│       ├── ThreatLockerAgent.ps1  # Agente Nativo Windows PowerShell (SHA-256 + Authenticode + Defender)
│       └── tl_agent_windows.py    # Agente Windows Python Multiplataforma
├── docs/
│   └── images/                # Capturas de tela ilustrativas (dados de exemplo sanitizados)
├── scripts/
│   └── install_systemd.sh     # Script de instalação automatizada dos serviços systemd em produção
├── requirements.txt
└── LICENSE
```

---

## ⚡ Instalação Rápida (Modo Produção)

### 1. Servidor Central + Agente Linux (Ubuntu / Debian / Kali)

```bash
git clone https://github.com/heavyscan/threatlocker-zt.git
cd threatlocker-zt
pip3 install -r requirements.txt
sudo bash scripts/install_systemd.sh
```

O painel estará disponível em:
- **Local**: `http://127.0.0.1:9443`
- **Rede Local (LAN / Wi-Fi)**: `http://<IP_DO_SERVIDOR>:9443`

### 2. Conectar um Endpoint Windows (PowerShell como Administrador)

```powershell
Invoke-WebRequest -Uri "http://<IP_DO_SERVIDOR>:9443/api/agents/download/windows-ps1" -OutFile ThreatLockerAgent.ps1
powershell -ExecutionPolicy Bypass -File .\ThreatLockerAgent.ps1 -ServerUrl "http://<IP_DO_SERVIDOR>:9443"
```

---

## 📄 Licença
Distribuído sob a licença **MIT**. Veja [LICENSE](LICENSE) para mais detalhes.
