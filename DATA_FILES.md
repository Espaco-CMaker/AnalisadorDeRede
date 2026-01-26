# Arquivos de Dados

Este diretório contém arquivos de dados que são gerados automaticamente:

## config.json
Arquivo de configuração local com:
- Configurações de ping e scan
- **device_nicknames**: Nomes personalizados vinculados aos MACs dos dispositivos

⚠️ **Este arquivo NÃO deve ser commitado no Git** (contém MACs da sua rede)

Copie `config.json.example` para `config.json` na primeira execução.

## oui_database.json
Banco de dados OUI (38.536 fabricantes) baixado do Wireshark.
- Tamanho: ~3 MB
- Atualização: Semanal automática
- Gerado por: `atualizador_oui.py`

⚠️ **Este arquivo NÃO deve ser commitado no Git** (muito grande e regenerável)

Execute `python atualizador_oui.py --update` para gerar.

## oui_metadata.json
Metadados sobre a última atualização do banco OUI:
- Data da última atualização
- Fonte dos dados
- Total de OUIs

⚠️ **Este arquivo NÃO deve ser commitado no Git** (gerado automaticamente)

---

**Nota**: Todos esses arquivos estão no `.gitignore` e são gerados automaticamente pela aplicação.
