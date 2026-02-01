# Analisador de Rede v2.2

## Descrição
Analisador de Rede é uma ferramenta completa para descoberta e monitoramento de dispositivos em redes locais. Realiza varredura ARP, identifica fabricantes via OUI database, executa medições de latência (ping) contínuas, descobre serviços por port scanning e fornece interface gráfica avançada em tempo real.

**Desenvolvido para**: Windows (recomendado com privilégios administrativos)  
**Linguagem**: Python 3.10+  
**Interface**: Tkinter (GUI nativa)  
**Versão**: 2.5.1 (Janeiro 2026)

## Como Iniciar (v2.2)

### Opção 1: PowerShell (Recomendado)
```powershell
.\iniciar.ps1
```

### Opção 2: Command Prompt
```cmd
iniciar.bat
```

### Opção 3: Manual
```powershell
.venv\Scripts\python.exe run.py
```

## Novas Features v2.2

### 1. Copiar Textos (Ctrl+C)
Selecione uma linha e pressione Ctrl+C para copiar todos os dados

### 2. Renomear Dispositivos
Duplo-clique na coluna MAC para dar um apelido persistente (salvo em config.json)

### 3. Abrir Portas
Clique direito na coluna SERVIÇOS para abrir serviços descobertos no navegador/aplicação

### 4. Gráfico: Timeouts em vermelho
Pontos de timeout são marcados com círculos vermelhos no gráfico para facilitar a identificação de perda de resposta.

## Instalação de Dependências---

## Funcionalidades Principais

### ✅ Varredura de Rede
- Detecção automática de interface ativa (IPv4)
- Varredura ARP da subnet local
- Numeração sequencial automática de dispositivos
- Prevenção de duplicatas garantida

### ✅ Identificação de Dispositivos
- Resolução de hostname via DNS
- Extração de MAC address
- Busca de fabricante (150+ entradas OUI + fallback online)
- Detecção de SO via análise de TTL
- Consulta NetBIOS para hosts Windows

### ✅ Medições de Latência
- Ping contínuo (5 tentativas por padrão)
- Cálculo de média em tempo real
- Gráfico Unicode dos últimos 15 pings
- Estatísticas: min | média | máx (ms)
- Taxa de sucesso de pacotes

### ✅ Interface Gráfica
- 3 abas: Dispositivos | Configurações | Logs
- Tabela interativa com colunas ordenáveis
- Destaque visual de linhas atualizadas
- Configurações persistentes
- Log com timestamps

---

## Instalação Rápida

### 1. Clonar/Baixar projeto
```bash
cd d:\+Espaço\ CMaker\Projetos\#2026\AnalisadorDeRede
```

### 2. Criar ambiente virtual (opcional)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Instalar dependências
```bash
pip install -r requirements.txt
```

### 4. Executar
```powershell
python analisador_rede_gui.py
```

---

## Uso da Interface

### Aba: Dispositivos

| Coluna | Descrição |
|--------|-----------|
| # | Número sequencial |
| IP | Endereço IPv4 |
| Hostname | Resolução DNS |
| NetBIOS | Nome Windows |
| Fabricante | Via OUI database |
| SO Detectado | Inferido por TTL |
| TTL | Time-to-Live |
| Bytes | Tamanho ICMP |
| Ping | Média + taxa sucesso (X/5) |
| Histórico | Gráfico dos últimos 15 pings |

**Botões**:
- **Iniciar**: Scan contínuo em loop
- **Parar**: Interrompe scan
- **Scan agora**: Varredura única

### Aba: Configurações
- Ajuste de tentativas de ping (1-20)
- Intervalo entre scans (10-900s)
- Salva automaticamente

### Aba: Logs
- Histórico com timestamps
- Eventos e erros

---

## Arquitetura

**analisador_rede.py** - Core de rede (790 linhas)
- Funções ARP, ping, DNS
- Base OUI (150+ fabricantes)
- Busca online fallback

**analisador_rede_gui.py** - Interface Tkinter (532 linhas)
- 3 abas com widgets
- Threading para não bloquear
- Persistência de configuração

---

## Dependências

```
tabulate>=0.9.0
```

Bibliotecas stdlib: tkinter, subprocess, socket, threading, json

---

## Versão Histórica

- **v2.0** (Janeiro 2026): Refatoração completa com threads, nova interface
- **v1.0** (Janeiro 2026): Versão inicial CLI

Ver [CHANGELOG.md](CHANGELOG.md) para detalhes completos.

---

## Autor
CMaker Projects - Análise e Monitoramento de Rede Local


```bash
python analisador_rede.py
```

### Linux/macOS

```bash
sudo python3 analisador_rede.py
```

## 📊 Saída esperada

```
======================================================================
               🌐 ANALISADOR DE REDE LOCAL
======================================================================

📡 Obtendo informações da rede...
✓ IP Local: 192.168.1.100
✓ Máscara: 255.255.255.0

🔎 Escaneando rede...
✓ 5 dispositivo(s) encontrado(s)

📊 Fazendo ping (isso pode levar alguns minutos)...
  [1/5] Pingando 192.168.1.1... 5.23 ms
  [2/5] Pingando 192.168.1.50... 45.67 ms
  ...

======================================================================
                     📋 RESULTADO DO SCAN
======================================================================

╒═════════════════╤═══════════════════════╤════════════════════════════╕
│ IP Address      │ MAC Address           │ Ping Médio (10 tentativas) │
╞═════════════════╪═══════════════════════╪════════════════════════════╡
│ 192.168.1.1     │ AA:BB:CC:DD:EE:FF     │         5.23 ms            │
│ 192.168.1.50    │ 11:22:33:44:55:66     │        45.67 ms            │
│ 192.168.1.100   │ 77:88:99:AA:BB:CC     │         2.15 ms            │
│ 192.168.1.150   │ DD:EE:FF:00:11:22     │        23.45 ms            │
│ 192.168.1.200   │ 33:44:55:66:77:88     │        78.90 ms            │
╘═════════════════╧═══════════════════════╧════════════════════════════╛

======================================================================
Total de dispositivos encontrados: 5
======================================================================
```

## 📝 Notas importantes

1. **Tempo de execução**: O programa pode levar 5-10 minutos, dependendo da quantidade de dispositivos e da velocidade da rede.

2. **Privilégios**: No Windows, recomenda-se executar como Administrador (uma mensagem de recomendação aparece ao abrir o app). No Linux/macOS, use `sudo`.

3. **Firewall**: Alguns dispositivos podem estar configurados para não responder a ping, aparecendo como "❌ Sem resposta".

4. **Cache ARP**: O programa popula o cache ARP fazendo ping para descobrir mais dispositivos. Isso é normal.

## 🐛 Solução de problemas

### "Comando não encontrado"
Certifique-se de ter instalado as dependências do requirements.txt:
```bash
pip install -r requirements.txt
```

### Poucos dispositivos encontrados
- Execute como Administrador (Windows) ou com `sudo` (Linux/macOS)
- Instale `arp-scan` ou `nmap` para melhor detecção
- Aguarde mais tempo para o programa completar

### Ping mostra "Sem resposta"
- Alguns dispositivos podem ter firewall que bloqueia ping
- Dispositivos offline não respondem
- É comportamento normal para alguns dispositivos

## 📄 Licença

MIT

## 👨‍💻 Autor

Desenvolvido para análise de rede local.
