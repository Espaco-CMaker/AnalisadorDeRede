# 📘 Guia Completo - Analisador de Rede

## 📋 Informações do Projeto

| Campo | Informação |
|-------|-----------|
| **Nome do Projeto** | Analisador de Rede |
| **Versão Atual** | 2.5 |
| **Status** | ✅ Ativo (Desenvolvimento Contínuo) |
| **Data de Criação** | Janeiro 2026 |
| **Última Atualização** | 26 de Janeiro de 2026 |
| **Linguagem** | Python 3.10+ |
| **Framework UI** | Tkinter (GUI Nativa) |
| **Plataforma** | Windows, Linux, macOS |
| **Plataforma Recomendada** | Windows (Com privilégios administrativos) |

---

## 👤 Autor e Organização

| Informação | Detalhe |
|-----------|--------|
| **Organização** | CMaker Projects / Espaço CMaker |
| **Localização** | d:\+Espaço CMaker\Projetos\#2026\AnalisadorDeRede |
| **Repositório GitHub** | [Espaco-CMaker/AnalisadorDeRede](https://github.com/Espaco-CMaker/AnalisadorDeRede) |
| **Branch Principal** | main |
| **Linguagem do Projeto** | Português (Brasil) |

---

## 🔐 Segurança e Dados Sensíveis

### ✅ Protegido pelo .gitignore

Os seguintes arquivos **NÃO** estão no GitHub por conterem dados sensíveis:

| Arquivo | Conteúdo Sensível | Status |
|---------|------------------|--------|
| `config.json` | Configurações locais e apelidos de dispositivos | ✅ Protegido |
| `ping_history.json` | Histórico de pings com IPs da rede | ✅ Protegido |
| `oui_database.json` | Cache local de fabricantes | ✅ Protegido |
| `oui_metadata.json` | Metadados da base OUI | ✅ Protegido |
| `.venv/` | Ambiente virtual do Python | ✅ Protegido |
| `build/` | Arquivos compilados PyInstaller | ✅ Protegido |
| `dist/` | Distribuíveis executáveis | ✅ Protegido |

### 🔓 Publicamente Disponível

Os seguintes arquivos **ESTÃO** no GitHub:

| Arquivo | Razão |
|---------|-------|
| `analisador_rede.py` | Código-fonte principal (sem dados) |
| `analisador_rede_gui.py` | Interface gráfica (sem dados) |
| `requirements.txt` | Dependências do projeto |
| `README.md` | Documentação gública |
| `CHANGELOG.md` | Histórico de versões |
| Exemplos e documentação | Guias e tutoriais |

### ⚠️ Dado Sensível Identificado

**Arquivo**: `config.json.example`
- Este é um arquivo **exemplo** sem dados reais
- Usado apenas como template
- **Seguro para GitHub**

---

## 📊 Versão Atual - v2.5

### Recursos Principais

#### 🖥️ **Tabela de Dispositivos** (Aba Principal)
- Status ONLINE/OFFLINE com cores visuais
- Filtro "Apenas online" para visualização rápida
- Coluna automática com MAC, IP, Hostname, NetBIOS
- Identificação de fabricante (150+ marcas OUI)
- Ping contínuo com gráfico em tempo real

#### 📊 **Gráfico Interativo de Ping**
- Tooltip ao passar o mouse mostrando hora e valor
- Histórico persistente (24h configurável)
- Estatísticas: Min, Máx, Média
- Suporta até 168 horas de dados
- Timeouts marcados por pontos vermelhos no gráfico

#### 🏷️ **Tabela de MACs/Nomes**
- Gerenciamento de apelidos persistentes
- Checkboxes para marcar/desmarcar MACs
- Filtros por MAC, Nome, IP, Gateway
- Bulk operations: Marcar filtrados, Apagar selecionados
- Importação/Exportação em CSV e TXT

#### ⚙️ **Configurações Personalizáveis**
- Tentativas de ping (1-20)
- Intervalo entre scans (10-900 segundos)
- Janela de histórico (1-168 horas)
- Salva automaticamente

#### 📝 **Logs em Tempo Real**
- Timestamps em todos os eventos
- Histórico completo de operações
- Rastreamento de erros

---

## 🔗 Links Importantes

| Recurso | Link |
|---------|------|
| **Repositório GitHub** | https://github.com/Espaco-CMaker/AnalisadorDeRede |
| **Issues e Bugs** | https://github.com/Espaco-CMaker/AnalisadorDeRede/issues |
| **Pull Requests** | https://github.com/Espaco-CMaker/AnalisadorDeRede/pulls |
| **Releases** | https://github.com/Espaco-CMaker/AnalisadorDeRede/releases |
| **Wiki** | https://github.com/Espaco-CMaker/AnalisadorDeRede/wiki |

---

## 📁 Estrutura do Projeto

```
AnalisadorDeRede/
├── analisador_rede.py           # Core de rede (1441 linhas)
├── analisador_rede_gui.py       # Interface GUI (2018 linhas)
├── launcher.py                  # Inicializador
├── run.py                       # Ponto de entrada
├── requirements.txt             # Dependências
├── config.json.example          # Exemplo de configuração
├── .gitignore                   # Proteção de sensíveis
├── README.md                    # Documentação principal
├── CHANGELOG.md                 # Histórico de versões
├── GUIA_PROJETO.md             # Este arquivo
├── iniciar.bat                  # Script inicialização Windows
├── iniciar.ps1                  # Script PowerShell
└── build/                       # PyInstaller output
```

---

## 📦 Dependências Principais

```
Python 3.10+
tkinter (nativa)
subprocess (nativa)
socket (nativa)
threading (nativa)
json (nativa)
re (nativa)
datetime (nativa)
platform (nativa)
```

**Instalação**:
```bash
pip install -r requirements.txt
```

---

## 🚀 Como Executar

### Opção 1: PowerShell (Recomendado)
```powershell
cd d:\+Espaço\ CMaker\Projetos\#2026\AnalisadorDeRede
.\iniciar.ps1
```

### Opção 2: Python Direto
```bash
python run.py
```

### Opção 3: Executável Compilado
```bash
# Criar executável:
pyinstaller analisador_rede_gui.py --onefile --icon=app.ico

# Executar:
dist/analisador_rede_gui.exe
```

---

## 🔄 Histórico de Versões

### v2.5 (26 Janeiro 2026) - **Versão Atual**
- ✅ Status ONLINE/OFFLINE em texto descritivo
- ✅ Cores ajustadas: ONLINE (sem fundo), OFFLINE (cinza médio)
- ✅ Filtro "Apenas online" na tabela de dispositivos
- ✅ Tooltip interativo no gráfico
- ✅ Reorganização de botões na aba de MACs
- ✅ Checkbox inteligente do cabeçalho

### v2.4 (Janeiro 2026)
- Persistência de dados avançada
- Histórico de ping com configuração de janela
- Bulk operations em MACs

### v2.3 (Janeiro 2026)
- Tabela de MACs com importação/exportação
- Sistema de filtros melhorado

### v2.2 (Janeiro 2026)
- Interface gráfica completa
- Copiar textos (Ctrl+C)
- Renomear dispositivos

### v2.1 (Janeiro 2026)
- Identificação de fabricante via OUI
- Port scanning

### v2.0 (Janeiro 2026)
- Refatoração com threads
- GUI com Tkinter

### v1.0 (Janeiro 2026)
- Versão inicial CLI

---

## 🛠️ Tecnologias Utilizadas

| Tecnologia | Uso |
|-----------|-----|
| **Python** | Linguagem principal |
| **Tkinter** | Interface gráfica |
| **Threading** | Operações assíncronas |
| **ARP** | Descoberta de dispositivos |
| **Ping/ICMP** | Medição de latência |
| **DNS** | Resolução de hostnames |
| **Socket** | Comunicação de rede |
| **JSON** | Persistência de dados |
| **RegEx** | Parse de outputs |

---

## 📊 Estatísticas do Código

| Métrica | Valor |
|---------|-------|
| **Linhas Totais** | ~3500+ |
| **Funções** | 50+ |
| **Classes** | 1 (AnalisadorRedeGUI) |
| **Threads** | Dinâmicas por dispositivo |
| **Documentação** | ~90% |

---

## 🎯 Objetivos e Funcionalidades

### ✅ Implementado
- Varredura ARP de rede local
- Ping contínuo com histórico
- Identificação de fabricante
- Interface gráfica responsiva
- Persistência de dados
- Filtros e buscas
- Gráficos em tempo real
- Importação/Exportação de dados
 - Detecção ONLINE via combinação ARP + TCP + Ping (quando disponível)

### 🔄 Em Desenvolvimento
 - Suporte a IPv6
 - Dashboard com estatísticas
 - Alertas automáticos

### 📋 Planejado
- Comparação de múltiplas redes
- Exportação em relatórios PDF
- Autenticação e multiplos usuários
- API REST

---

## 🔐 Boas Práticas de Segurança

1. **Nunca commitar dados sensíveis**
   - config.json está em .gitignore ✅
   - ping_history.json está protegido ✅

2. **Ambiente Virtual**
   - Use `.venv/` para isolamento ✅
   - Dependências fixadas em requirements.txt ✅

3. **Controle de Acesso**
   - Execute como administrador (Windows)
   - Use privilégios mínimos necessários

4. **Auditoria de Commits**
   - Todos os commits incluem mensagens descritivas ✅
   - Histórico rastreável no GitHub ✅

---

## 📞 Suporte e Contribuição

### Relatar Bugs
Abra uma issue no GitHub com:
- Versão do Python
- Sistema Operacional
- Passos para reproduzir
- Mensagem de erro (se houver)

### Contribuir
1. Faça fork do repositório
2. Crie branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add AmazingFeature'`)
4. Push para o branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

## 📄 Licença

MIT License - Veja LICENSE.md para detalhes

---

## 📞 Contato

**Espaço CMaker**
- Local: d:\+Espaço CMaker\Projetos\#2026\
- GitHub: https://github.com/Espaco-CMaker/
- Repositório: https://github.com/Espaco-CMaker/AnalisadorDeRede

---

## 📌 Notas Importantes

- ✅ **Seguro para GitHub**: Todos os dados sensíveis estão protegidos
- ✅ **Open Source**: Código disponível para análise
- ✅ **Documentado**: Múltiplos arquivos de guia
- ✅ **Mantido Ativamente**: Atualizações regulares
- ⚠️ **Requer Privilégios**: Execute como admin para melhor performance

---

**Gerado em**: 26 de Janeiro de 2026  
**Versão deste Guia**: 1.0
