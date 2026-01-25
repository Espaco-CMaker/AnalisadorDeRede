# Changelog - Analisador de Rede

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

---

## [2.0] - 2026-01-25

### ✨ Novidades

#### Interface Gráfica (GUI Tkinter)
- Interface com 3 abas principais: Dispositivos, Configurações, Logs
- Tabela interativa com 10 colunas ordenáveis
- Gráfico Unicode em tempo real (min | média | máx)
- Destaque visual (amarelo) de linhas atualizadas
- Log com timestamps automáticos

#### Identificação de Dispositivos
- Suporte a 150+ fabricantes (OUI database)
- Detecção de SO via TTL (Windows/Linux/Cisco)
- Consulta NetBIOS para hosts Windows (nbtstat)
- Resolução DNS de hostnames
- Busca online fallback (macaddress.io)

#### Equipamentos Especializados
- **Chineses**: MediaTek, Rockchip, Allwinner, Tenda, Cudy, Sonoff
- **IoT**: Espressif (ESP32/ESP8266), Sonoff
- **DVR/Câmeras**: Techwell, Grain Media, Actions Semi
- **Impressoras**: Brother, Canon, Xerox

#### Configuração
- Arquivo `config.json` para persistência
- Ajuste de tentativas de ping (1-20)
- Ajuste de intervalo entre scans (10-900s)
- Salva automático ao alterar
- Carrega automático ao iniciar

#### Threading & Performance
- Scan não bloqueia interface (daemon thread)
- Fila (Queue) para comunicação thread-safe
- Atualização em tempo real de cada dispositivo
- Prevenção garantida de duplicatas

#### Logs & Debug
- Histórico com timestamps
- Eventos de scan, dispositivos, erros
- Rastreamento de histórico de pings (20 últimas medições)

### 🔧 Melhorias Técnicas

#### Robustez Windows
- Suporte a múltiplos encodings (utf-8 → cp1252 → cp850 → latin-1)
- Detecção de interface via netsh com fallback ipconfig
- Tratamento de caracteres acentuados em português
- Suporte a nomes de usuário com espaços

#### Deduplicação
- Dicionário de rastreamento {ip: item_id} para O(1) lookup
- Nunca insere IP duplicado, sempre atualiza
- Sincronização automática ao limpar tabela

#### Gráfico de Ping
- Normalização automática min/max
- 15 barras Unicode para visualizar tendência
- Cálculo de média, min, máx
- Taxa de sucesso de pacotes (X/5)

### 📊 Estrutura de Dados

```python
# Histórico de pings por IP
self.ping_history = {
    "192.168.1.10": [15.2, 14.8, 15.1, ...],  # últimos 20
    "192.168.1.11": [45.3, 46.1, 45.8, ...],
}

# Rastreamento de IPs na tabela
self.table_ips = {
    "192.168.1.10": "item_001",
    "192.168.1.11": "item_002",
}
```

### 🐛 Correções (desde v1.0)

- ✅ UnicodeDecodeError em Windows resolvido com fallback de encoding
- ✅ Caracteres acentuados (Máscara/Mascara) tratados com regex flexível
- ✅ Duplicatas eliminadas com dicionário de rastreamento
- ✅ Tabela não se limpa mais, apenas atualiza linhas existentes
- ✅ Gráfico agora sempre visível com min/média/máx

---

## [1.0] - 2026-01-24

### ✨ Funcionalidades Iniciais

#### CLI - Interface de Linha de Comando
- Varredura ARP da subnet local
- Resolução de IP/MAC via ipconfig + arp
- Medição de ping (10 tentativas)
- Cálculo de média de latência
- Exibição em tabela (tabulate)
- Listagem clara: IP | MAC | Ping Médio

#### Identificação de Dispositivos (Básica)
- Resolução DNS de hostnames
- OUI database inicial (~10 entradas)
- Detecção simplificada de SO via TTL

#### Compatibilidade
- Windows (ipconfig, arp, ping)
- Linux/macOS (ifconfig, arp, ping)
- Suporte a fallback de ferramentas

### 📋 Mudanças

- Inicial release com funcionalidades básicas
- Foco em Windows (ferramentas nativas)
- Implementação simples sem GUI
- OUI database mínima

---

## Plano Futuro (v3.0+)

### 🎯 Em Consideração

- [ ] Export CSV/JSON de resultados
- [ ] Filtro por fabricante/SO
- [ ] Port scanning opcional
- [ ] Packet capture com tcpdump
- [ ] Alertas de dispositivos novos/desaparecidos
- [ ] Dark theme para interface
- [ ] Comparação com baseline anterior
- [ ] Integração com SNMP
- [ ] API REST para automação
- [ ] Suporte Linux/macOS nativo

---

## Notas de Desenvolvimento

### Ambiente
- Python 3.10+
- Tkinter (stdlib)
- tabulate 0.9.0+

### Testes Realizados
- ✅ Windows 10/11 com admin
- ✅ Múltiplas interfaces de rede
- ✅ Redes com 3-50+ dispositivos
- ✅ Encoding misto (ASCII/UTF-8/cp1252)
- ✅ Scan contínuo por horas

### Contribuidores
- CMaker Projects Team

---

**Última atualização**: 25 de janeiro de 2026
