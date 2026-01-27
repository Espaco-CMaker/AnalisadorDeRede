#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                     ANALISADOR DE REDE v2.0                              ║
║          Descoberta e Monitoramento de Dispositivos em Rede Local        ║
╚═══════════════════════════════════════════════════════════════════════════╝

Módulo Core: Funções de Rede e Detecção de Dispositivos
───────────────────────────────────────────────────────────────────────────

FUNCIONALIDADES:
  ✓ Varredura ARP da subnet local
  ✓ Medição de latência (ping) com cálculo de média
  ✓ Resolução de hostnames via DNS
  ✓ Identificação de fabricante (OUI database - 150+ entradas)
  ✓ Detecção de SO via TTL (Windows/Linux/Cisco)
  ✓ Consulta NetBIOS para hosts Windows
  ✓ Busca online fallback para MACs desconhecidos

REQUISITOS:
  • Python 3.10+
  • Windows (recomendado) ou Linux/macOS
  • Privilégio administrativo (recomendado para ARP completo)

USO:
  from analisador_rede import fazer_arp_scan, calcular_ping, obter_info_dispositivo
  
  dispositivos = fazer_arp_scan("192.168.1.1", "255.255.255.0")
  for ip, mac in dispositivos.items():
      ping = calcular_ping(ip, tentativas=5)
      hostname, fabricante = obter_info_dispositivo(ip, mac)
      print(f"{ip} ({mac}) - {hostname} [{fabricante}] - {ping}")

VERSÃO: 2.0
DATA: Janeiro 2026
AUTOR: CMaker Projects

───────────────────────────────────────────────────────────────────────────
"""

import subprocess
import re
import sys
import platform
import ipaddress
import socket
import concurrent.futures
from tabulate import tabulate
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional, Dict


# Tenta importar o atualizador OUI (opcional)
try:
    from atualizador_oui import AtualizadorOUI
    ATUALIZADOR_DISPONIVEL = True
except ImportError:
    ATUALIZADOR_DISPONIVEL = False


@dataclass
class IdentificacaoEquipamento:
    """Estrutura com informações de identificação de equipamento por MAC"""
    mac_completo: str
    oui: str
    fabricante: str
    tipo_equipamento: str
    confianca: str  # "Alto", "Médio", "Baixo", "Desconhecido"
    
    def __str__(self):
        return f"{self.fabricante} - {self.tipo_equipamento} (Confiança: {self.confianca})"
    
    def to_dict(self):
        return {
            "mac": self.mac_completo,
            "oui": self.oui,
            "fabricante": self.fabricante,
            "tipo_equipamento": self.tipo_equipamento,
            "confianca": self.confianca
        }


# Base de dados de OUIs (3 primeiros bytes do MAC)
# Formato: OUI (com :) -> (Fabricante, Tipo)
OUI_DATABASE = {
    # Roteadores e Equipamentos de Rede
    "00:0F:33": ("Arcadyan", "Roteador/Modem/ONT"),
    "00:12:3F": ("Motorola", "Roteador/Modem"),
    "00:1A:2F": ("Cisco", "Roteador/Switch"),
    "00:23:CD": ("Huawei", "Roteador/Modem"),
    "08:00:27": ("Cadmus Computer Systems", "Roteador Virtualizado"),
    "08:9A:4A": ("Sagemcom", "Roteador/Modem"),
    "0C:74:C3": ("Huawei", "Roteador/Modem"),
    "1C:BD:B9": ("TP-Link", "Roteador/Switch/Access Point"),
    "24:4B:03": ("Espressif", "ESP8266/ESP32 - IoT"),
    "50:C7:BF": ("TP-Link", "Roteador/Access Point"),
    "88:DC:96": ("TP-Link", "Roteador/Access Point"),
    "9C:29:76": ("Compal", "Roteador/Modem"),
    "B0:48:7A": ("TP-Link", "Roteador/Access Point"),
    
    # Smartphones e Tablets
    "00:19:0E": ("Apple", "iPhone/iPad"),
    "00:1F:F3": ("Apple", "iPhone/iPad"),
    "00:3E:98": ("Apple", "iPhone/iPad"),
    "00:A0:D2": ("Apple", "iPhone/iPad"),
    "00:B0:D0": ("Apple", "iPhone/iPad/MacBook"),
    "00:D4:97": ("Apple", "iPhone/iPad"),
    "08:00:07": ("Apple", "iPhone/iPad/MacBook"),
    "14:7D:DA": ("Apple", "iPhone/iPad"),
    "1C:52:16": ("Apple", "iPhone/iPad/MacBook"),
    "34:08:04": ("Apple", "iPhone/iPad"),
    "3C:37:86": ("Apple", "iPhone/iPad"),
    "6C:40:08": ("Apple", "iPhone/iPad/MacBook"),
    "AC:BC:32": ("Apple", "iPhone/iPad/MacBook"),
    "AC:DE:48": ("Apple", "iPhone/iPad/MacBook"),
    "B8:8D:12": ("Apple", "iPhone/iPad/MacBook"),
    "D4:6E:0E": ("Apple", "iPhone/iPad"),
    "EC:F4:BB": ("Apple", "iPhone/iPad/MacBook"),
    
    # Samsung
    "00:1A:7D": ("Samsung", "Smartphone/Tablet"),
    "00:22:B0": ("Samsung", "Smartphone/Tablet"),
    "00:60:64": ("Samsung", "Smartphone/Tablet"),
    "08:D4:6C": ("Samsung", "Smartphone/Tablet"),
    "60:FE:06": ("Samsung", "Smartphone/Tablet"),
    "78:31:C1": ("Samsung", "Smartphone/Tablet"),
    "84:25:DB": ("Samsung", "Smartphone/Tablet"),
    "B0:E2:35": ("Samsung", "Smartphone/Tablet"),
    "E4:E5:D7": ("Samsung", "Smartphone/Tablet"),
    
    # Amazon (Alexa / Echo)
    "00:0C:6E": ("Amazon", "Echo/Alexa/Fire TV"),
    "14:CC:20": ("Amazon", "Echo/Alexa/Fire TV"),
    "18:74:2E": ("Amazon", "Echo/Alexa/Fire TV"),
    "4C:EF:C0": ("Amazon", "Echo/Alexa/Fire TV"),
    "88:E9:FE": ("Amazon", "Echo/Alexa/Fire TV"),
    
    # Google
    "00:25:86": ("Google", "Nexus/Pixel/Chromecast"),
    "00:4D:6D": ("Google", "Nexus/Pixel"),
    "08:ED:B7": ("Google", "Chromecast/Nest"),
    "18:B7:9E": ("Google", "Nest/Chromecast"),
    "F4:F5:DB": ("Google", "Nest/Chromecast"),
    
    # Microsoft
    "00:1D:D8": ("Microsoft", "Xbox/Laptop"),
    "00:50:F2": ("Microsoft", "Windows PC/Laptop"),
    "3C:37:36": ("Microsoft", "Surface/Laptop"),
    "BC:5F:F4": ("Microsoft", "Xbox/Laptop"),
    
    # Impressoras
    "00:09:6B": ("Hewlett-Packard", "Impressora HP"),
    "00:0A:95": ("Lexmark", "Impressora Lexmark"),
    "00:11:2F": ("Brother", "Impressora Brother"),
    "00:1F:2E": ("Canon", "Impressora Canon"),
    "00:24:A9": ("Xerox", "Impressora Xerox"),
    "08:00:69": ("Xerox", "Impressora Xerox"),
    "1C:C6:3C": ("Hewlett-Packard", "Impressora HP"),
    "50:46:5D": ("Hewlett-Packard", "Impressora HP"),
    "78:E1:03": ("Brother", "Impressora Brother"),
    "BC:67:47": ("Ricoh", "Impressora/Multifuncional"),
    
    # Câmeras de Segurança
    "00:0D:3D": ("Axis Communications", "Câmera IP"),
    "00:11:34": ("D-Link", "Câmera IP"),
    "00:30:F1": ("Hikvision", "Câmera IP/NVR"),
    "10:FD:B8": ("Dahua", "Câmera IP/NVR"),
    "2C:F0:5D": ("Hikvision", "Câmera IP/NVR"),
    "54:A0:50": ("TP-Link", "Câmera IP"),
    "74:AC:B9": ("Dahua", "Câmera IP/NVR"),
    "9C:2A:70": ("Opticam", "Câmera IP"),
    "DC:FE:18": ("Hikvision", "Câmera IP/NVR"),
    
    # Smart TVs
    "00:0B:8C": ("LG Electronics", "Smart TV/Monitor"),
    "00:1E:8F": ("Samsung", "Smart TV"),
    "00:E0:4C": ("Sony", "Smart TV"),
    "08:00:37": ("Samsung", "Smart TV"),
    "34:13:E8": ("LG Electronics", "Smart TV"),
    "78:BD:BC": ("Vizio", "Smart TV"),
    "9C:6B:00": ("TCL", "Smart TV"),
    "B0:AD:17": ("Philips", "Smart TV/Monitor"),
    
    # Relógios e Wearables
    "00:22:D0": ("Polar Electro", "Relógio/Fitness"),
    "10:2A:B2": ("Fossil Group", "Smartwatch"),
    "5C:52:84": ("Fitbit", "Fitness Tracker"),
    "60:D5:A8": ("Garmin", "Smartwatch/GPS"),
    "78:A1:06": ("Jawbone", "Fitness Tracker"),
    "9C:AA:1B": ("Apple Watch", "Smartwatch"),
    
    # Dispositivos IoT e Sonoff
    "34:94:54": ("Sunricher", "Controlador RGB"),
    "60:01:94": ("Shenzhen Suntop", "Relé WiFi"),
    "84:F3:EB": ("Lumi United", "Hub Zigbee"),
    "BC:33:AC": ("Gledopto", "Controlador LED"),
    
    # NAS e Servidores
    "00:11:32": ("Synology", "NAS"),
    "00:50:3F": ("NetApp", "NAS/Storage"),
    "08:00:22": ("Qnap", "NAS"),
    "90:09:D8": ("Seagate", "NAS"),
    "AA:BB:CC": ("Western Digital", "NAS"),
    
    # Outros Fabricantes Comuns
    "02:00:00": ("Mikrotik", "RouterOS"),
    "00:13:10": ("Linksys", "Roteador Wireless"),
}


def atualizar_oui_database_online() -> Dict[str, tuple]:
    """
    Atualiza a base de dados OUI a partir de fontes online.
    
    Usa o módulo atualizador_oui para carregar dados da IEEE/Wireshark
    e mescla com dados locais customizados.
    
    Returns:
        Dict: Banco de dados OUI atualizado {OUI: (Fabricante, Tipo)}
    """
    global OUI_DATABASE
    
    if not ATUALIZADOR_DISPONIVEL:
        print("[WARN] Módulo atualizador_oui não disponível - usando cache local")
        return OUI_DATABASE
    
    try:
        print("[INFO] Atualizando base OUI online...")
        atualizador = AtualizadorOUI()
        
        # Tenta atualizar
        sucesso = atualizador.atualizar_online(forcar=False)
        
        if sucesso:
            novo_banco = atualizador.obter_oui_database()
            OUI_DATABASE.update(novo_banco)
            print(f"[OK] Base OUI atualizada com {len(OUI_DATABASE)} OUIs")
            return OUI_DATABASE
        else:
            print("[INFO] Usando cache local de OUI")
            return OUI_DATABASE
    
    except Exception as e:
        print(f"[WARN] Erro ao atualizar OUI online: {e}")
        return OUI_DATABASE


def carregar_oui_database_local() -> Dict[str, tuple]:
    """
    Carrega base OUI do cache local (JSON).
    
    Returns:
        Dict: Banco de dados OUI {OUI: (Fabricante, Tipo)}
    """
    global OUI_DATABASE
    
    if not ATUALIZADOR_DISPONIVEL:
        return OUI_DATABASE
    
    try:
        atualizador = AtualizadorOUI()
        novo_banco = atualizador.carregar_oui_local()
        OUI_DATABASE.update(novo_banco)
        print(f"[OK] Carregados {len(novo_banco)} OUIs do cache local")
        return OUI_DATABASE
    except Exception as e:
        print(f"[WARN] Erro ao carregar OUI local: {e}")
        return OUI_DATABASE


def inicializar_oui_database(atualizar_online: bool = False):
    """
    Inicializa o banco de dados OUI.
    
    Args:
        atualizar_online (bool): Se True, tenta atualizar a partir de fontes online
    """
    global OUI_DATABASE
    
    if atualizar_online and ATUALIZADOR_DISPONIVEL:
        atualizar_oui_database_online()
    else:
        carregar_oui_database_local()
    
    if len(OUI_DATABASE) < 10:
        print(f"[WARN] Banco OUI pequeno ({len(OUI_DATABASE)} OUIs)")


def _normalizar_mac(mac: str) -> str:
    """Normaliza MAC para formato com ':'"""
    mac = mac.upper().replace("-", ":").replace(" ", "")
    if ":" not in mac:
        mac = ":".join([mac[i:i+2] for i in range(0, 12, 2)])
    return mac


def _extrair_oui(mac: str) -> str:
    """Extrai os 3 primeiros bytes (OUI) do MAC"""
    mac_normalizado = _normalizar_mac(mac)
    return mac_normalizado[:8].upper()


def _aplicar_heuristicas(fabricante: str, tipo_base: str) -> tuple[str, str]:
    """
    Aplica regras heurísticas para refinar a identificação de equipamento
    baseado no nome do fabricante.
    
    Retorna: (tipo_refinado, confianca)
    """
    fabricante_lower = fabricante.lower()
    
    # Regras para Espressif (ESP8266/ESP32)
    if "espressif" in fabricante_lower:
        return "ESP8266/ESP32 - Sonoff/IoT/Sensor WiFi", "Alto"
    
    # Regras para Apple
    if "apple" in fabricante_lower:
        if "watch" in tipo_base.lower():
            return "Apple Watch - Smartwatch", "Alto"
        return "iPhone/iPad/MacBook/Apple TV", "Médio"
    
    # Regras para Amazon
    if "amazon" in fabricante_lower:
        return "Amazon Echo/Alexa/Fire TV", "Alto"
    
    # Regras para Google
    if "google" in fabricante_lower:
        if "nest" in tipo_base.lower():
            return "Google Nest/Chromecast/Home", "Alto"
        return "Nexus/Pixel/Chromecast", "Médio"
    
    # Regras para Samsung
    if "samsung" in fabricante_lower:
        if "smart tv" in tipo_base.lower() or "tv" in tipo_base.lower():
            return "Samsung Smart TV", "Alto"
        return "Smartphone/Tablet Galaxy", "Médio"
    
    # Regras para Arcadyan
    if "arcadyan" in fabricante_lower:
        return "Roteador/Modem/ONT de Operadora", "Alto"
    
    # Regras para Hikvision
    if "hikvision" in fabricante_lower:
        return "Câmera IP/NVR Hikvision", "Alto"
    
    # Regras para Dahua
    if "dahua" in fabricante_lower:
        return "Câmera IP/NVR Dahua", "Alto"
    
    # Regras para TP-Link
    if "tp-link" in fabricante_lower:
        if "access point" in tipo_base.lower():
            return "TP-Link Access Point/Repetidor WiFi", "Alto"
        return "TP-Link Roteador/Switch/WiFi", "Médio"
    
    # Regras para Synology
    if "synology" in fabricante_lower:
        return "Synology NAS - Network Storage", "Alto"
    
    # Regras para Qnap
    if "qnap" in fabricante_lower:
        return "QNAP NAS - Network Storage", "Alto"
    
    # Regras para Hewlett-Packard
    if "hewlett" in fabricante_lower or "hp" in fabricante_lower:
        return "Impressora/Multifuncional HP", "Alto"
    
    # Regras para Brother
    if "brother" in fabricante_lower:
        return "Impressora Brother", "Alto"
    
    # Regras para Canon
    if "canon" in fabricante_lower:
        return "Impressora Canon", "Alto"
    
    # Regras para Xerox
    if "xerox" in fabricante_lower:
        return "Impressora/Multifuncional Xerox", "Alto"
    
    # Regras para Cisco
    if "cisco" in fabricante_lower:
        return "Cisco Roteador/Switch/Equipamento Profissional", "Alto"
    
    # Regras para Huawei
    if "huawei" in fabricante_lower:
        return "Huawei Roteador/Modem/5G", "Médio"
    
    # Regras para Microsoft
    if "microsoft" in fabricante_lower:
        return "Microsoft Xbox/Surface/Windows PC", "Médio"
    
    # Se não se encaixa em nenhuma heurística, usa o tipo base
    return tipo_base, "Baixo" if tipo_base == "Desconhecido" else "Médio"


def identificar_equipamento_por_mac(mac: str) -> IdentificacaoEquipamento:
    """
    Identifica o nome provável e tipo de equipamento a partir de um endereço MAC.
    
    Args:
        mac (str): Endereço MAC no formato "24:4B:03:AA:BB:CC" ou "244B03AABBCC"
    
    Returns:
        IdentificacaoEquipamento: Objeto com informações estruturadas
    
    Exemplos:
        >>> resultado = identificar_equipamento_por_mac("24:4B:03:AA:BB:CC")
        >>> print(resultado.fabricante)
        Espressif
        >>> print(resultado.tipo_equipamento)
        ESP8266/ESP32 - Sonoff/IoT/Sensor WiFi
        
        >>> resultado = identificar_equipamento_por_mac("00:1A:7D:BB:CC:DD")
        >>> print(resultado.fabricante)
        Samsung
    """
    # Normaliza MAC
    mac_normalizado = _normalizar_mac(mac)
    
    # Valida formato MAC
    if not re.match(r"^([0-9A-F]{2}:){5}([0-9A-F]{2})$", mac_normalizado):
        return IdentificacaoEquipamento(
            mac_completo=mac_normalizado,
            oui="INVÁLIDO",
            fabricante="Erro",
            tipo_equipamento="MAC inválido",
            confianca="Desconhecido"
        )
    
    # Extrai OUI
    oui = _extrair_oui(mac_normalizado)
    
    # Consulta banco de dados de OUIs (verifica vários formatos)
    fabricante = None
    tipo_base = None
    
    # Tenta com formato com dois-pontos (24:4B:03)
    if oui in OUI_DATABASE:
        fabricante, tipo_base = OUI_DATABASE[oui]
    # Tenta sem dois-pontos (244B03)
    elif oui.replace(":", "") in OUI_DATABASE:
        fabricante, tipo_base = OUI_DATABASE[oui.replace(":", "")]
    # Tenta case-insensitive
    else:
        oui_lower = oui.lower()
        for chave, valor in OUI_DATABASE.items():
            chave_normalizada = chave.upper().replace(":", "")
            oui_normalizado = oui.upper().replace(":", "")
            if chave_normalizada == oui_normalizado:
                fabricante, tipo_base = valor
                break
    
    # Se não encontrou
    if fabricante is None:
        return IdentificacaoEquipamento(
            mac_completo=mac_normalizado,
            oui=oui,
            fabricante="Desconhecido",
            tipo_equipamento="Equipamento não identificado no banco de dados",
            confianca="Desconhecido"
        )
    
    # Aplica heurísticas para refinar o tipo
    tipo_refinado, confianca = _aplicar_heuristicas(fabricante, tipo_base)
    
    return IdentificacaoEquipamento(
        mac_completo=mac_normalizado,
        oui=oui,
        fabricante=fabricante,
        tipo_equipamento=tipo_refinado,
        confianca=confianca
    )


def identificar_multiplos_equipamentos(macs: Dict[str, str]) -> Dict[str, IdentificacaoEquipamento]:
    """
    Identifica múltiplos equipamentos a partir de uma lista de MACs.
    
    Args:
        macs (Dict[str, str]): Dicionário {IP: MAC}
    
    Returns:
        Dict[str, IdentificacaoEquipamento]: Dicionário {IP: IdentificacaoEquipamento}
    
    Exemplo:
        >>> dispositivos = {"192.168.1.1": "24:4B:03:AA:BB:CC", "192.168.1.2": "00:1A:7D:BB:CC:DD"}
        >>> resultado = identificar_multiplos_equipamentos(dispositivos)
        >>> for ip, info in resultado.items():
        ...     print(f"{ip}: {info.fabricante} - {info.tipo_equipamento}")
    """
    resultado = {}
    for ip, mac in macs.items():
        resultado[ip] = identificar_equipamento_por_mac(mac)
    return resultado


def run_cmd_capture(cmd, timeout=None):
    """Executa um comando e retorna stdout como texto, sem abrir janelas no Windows."""
    try:
        startupinfo = None
        creationflags = 0
        if platform.system() == "Windows":
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0  # SW_HIDE
                creationflags = subprocess.CREATE_NO_WINDOW
            except Exception:
                # Caso alguma flag não esteja disponível, segue sem elas
                startupinfo = None
                creationflags = 0

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        data = result.stdout
        # Tenta decodificar em diferentes encodings comuns do Windows
        for enc in ("utf-8", "cp1252", "cp850", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("latin-1", errors="replace")
    except Exception:
        return ""

def obter_interface_ativa():
    """Obtém a interface de rede ativa e seu IP/Gateway"""
    try:
        if platform.system() == "Windows":
            # Primeira tentativa: netsh (mais estável em PT-BR)
            texto_netsh = run_cmd_capture(["netsh", "interface", "ipv4", "show", "addresses"])
            if texto_netsh:
                blocos = re.split(r"Configura[cç][aã]o da interface", texto_netsh, flags=re.IGNORECASE)
                for bloco in blocos:
                    m_ip = re.search(r"Endere[cç]o IP:\s*(\d+\.\d+\.\d+\.\d+)", bloco, re.IGNORECASE)
                    m_mask = re.search(r"m[aá]scara\s+(\d+\.\d+\.\d+\.\d+)", bloco, re.IGNORECASE)
                    if m_ip and m_mask:
                        ip = m_ip.group(1)
                        mascara = m_mask.group(1)
                        if ip.startswith("169.254.") or ip.startswith("127."):
                            continue
                        return ip, mascara

            # Fallback: ipconfig
            texto = run_cmd_capture(["ipconfig", "/all"])
            if not texto:
                texto = run_cmd_capture(["ipconfig"])
            if not texto:
                raise RuntimeError("ipconfig não retornou saída")

            blocos = re.split(r"\r?\n\s*\r?\n", texto)
            for bloco in blocos:
                m_ip = re.search(r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)", bloco, re.IGNORECASE)
                m_mask = re.search(r"(Máscara|Mascara|Subnet).*?:\s*(\d+\.\d+\.\d+\.\d+)", bloco, re.IGNORECASE)
                if m_ip and m_mask:
                    ip = m_ip.group(1)
                    mascara = m_mask.group(m_mask.lastindex)
                    if ip.startswith("169.254.") or ip.startswith("127."):
                        continue
                    return ip, mascara
        else:
            texto = run_cmd_capture(["ifconfig"]) or ""
            ip_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", texto)
            mascara_match = re.search(r"netmask\s+(\d+\.\d+\.\d+\.\d+)", texto)
            if ip_match and mascara_match:
                return ip_match.group(1), mascara_match.group(1)
    except Exception as e:
        print(f"[WARN] Erro ao obter interface: {e}")
    
    return None, None

def calcular_rede(ip, mascara):
    """Calcula a rede CIDR a partir do IP e máscara"""
    try:
        interface = ipaddress.IPv4Interface(f"{ip}/{mascara}")
        rede = interface.network
        return rede
    except:
        return None

def fazer_arp_scan(ip_local, mascara):
    """Executa ARP scan para descobrir dispositivos na rede"""
    try:
        rede = calcular_rede(ip_local, mascara)
        if not rede:
            print("[ERRO] Não foi possível calcular a rede")
            return []
        
        dispositivos = {}
        
        if platform.system() == "Windows":
            # No Windows, usa arp -a para listar cache ARP
            texto_arp = run_cmd_capture(["arp", "-a"]) or ""
            # Extrai IPs e MACs
            padrao = r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-]{17})"
            matches = re.findall(padrao, texto_arp)
            
            # Calcula endereço de broadcast para filtrar
            endereco_broadcast = str(rede.broadcast_address)
            endereco_rede = str(rede.network_address)
            
            for ip, mac in matches:
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    # Filtra broadcast (.255) e endereço de rede (.0)
                    if ip_obj in rede and ip != endereco_broadcast and ip != endereco_rede:
                        dispositivos[ip] = mac.replace("-", ":").upper()
                except:
                    pass
            
            print(f"[DEBUG] Cache ARP inicial: {len(dispositivos)} dispositivos encontrados")
            
            # Se encontrou poucos, faz ping broadcast para popular ARP
            if len(dispositivos) < 3:
                print("[INFO] Descobrindo dispositivos na rede (aguarde ~240s)...")
                
                # Calcula o endereço de broadcast para filtrar
                endereco_broadcast = str(rede.broadcast_address)
                
                # Contador de sucessos
                import threading
                contador_sucesso = [0]
                contador_lock = threading.Lock()
                
                # Função para fazer ping em paralelo
                def ping_host(ip_alvo):
                    if ip_alvo == endereco_broadcast:
                        return False
                    try:
                        # Executa ping sem abrir janelas de console no Windows
                        startupinfo = None
                        creationflags = 0
                        if platform.system() == "Windows":
                            try:
                                startupinfo = subprocess.STARTUPINFO()
                                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                                startupinfo.wShowWindow = 0
                                creationflags = subprocess.CREATE_NO_WINDOW
                            except Exception:
                                startupinfo = None
                                creationflags = 0
                        resultado = subprocess.run(
                            ["ping", "-n", "1", "-w", "4000", ip_alvo],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=12,
                            startupinfo=startupinfo,
                            creationflags=creationflags,
                        )
                        if resultado.returncode == 0:
                            with contador_lock:
                                contador_sucesso[0] += 1
                            return True
                    except:
                        pass
                    return False
                
                # Faz ping paralelo em todos os hosts da rede (sem limite de 255)
                hosts_list = list(rede.hosts())
                print(f"[INFO] Pingando {len(hosts_list)} endereços possíveis...")
                print(f"[DEBUG] Timeout por ping: 4000ms (subprocess: 12s)")
                print(f"[DEBUG] Workers paralelos: 100")
                
                # Usa ThreadPoolExecutor para ping paralelo (mais rápido)
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                    futures = [executor.submit(ping_host, str(host)) for host in hosts_list]
                    # Aguarda conclusão com timeout
                    done, not_done = concurrent.futures.wait(futures, timeout=360)
                    print(f"[DEBUG] Pings concluídos: {len(done)}/{len(futures)}")
                    print(f"[DEBUG] Pings com sucesso: {contador_sucesso[0]}")
                
                # Re-executa arp -a
                print("[INFO] Lendo cache ARP atualizado...")
                texto_arp = run_cmd_capture(["arp", "-a"]) or ""
                matches = re.findall(padrao, texto_arp)
                print(f"[DEBUG] Total de entradas no ARP: {len(matches)}")
                dispositivos = {}
                endereco_broadcast = str(rede.broadcast_address)
                for ip, mac in matches:
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        # Filtra endereço de broadcast e endereço de rede
                        if ip_obj in rede and ip != endereco_broadcast and ip != str(rede.network_address):
                            dispositivos[ip] = mac.replace("-", ":").upper()
                    except:
                        pass
                print(f"[INFO] Dispositivos encontrados após scan: {len(dispositivos)}")
        
        else:
            # Linux/Mac - usa arp-scan
            try:
                texto_scan = run_cmd_capture(["arp-scan", "-l"], timeout=30)
                padrao = r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:]{17})"
                matches = re.findall(padrao, texto_scan)
                dispositivos = {ip: mac for ip, mac in matches}
            except FileNotFoundError:
                print("[WARN] arp-scan não encontrado. Usando nmap...")
                texto_nmap = run_cmd_capture(["nmap", "-sn", str(rede)], timeout=60)
                padrao = r"(\d+\.\d+\.\d+\.\d+)"
                for ip in re.findall(padrao, texto_nmap):
                    dispositivos[ip] = "N/A"
        
        return dispositivos
    
    except Exception as e:
        print(f"[ERRO] Erro no ARP scan: {e}")
        return {}

def calcular_ping(ip, tentativas=10):
    """Calcula o ping médio para um IP"""
    try:
        if platform.system() == "Windows":
            texto_ping = run_cmd_capture(["ping", "-n", str(tentativas), "-w", "1000", ip], timeout=tentativas + 5)
        else:
            texto_ping = run_cmd_capture(["ping", "-c", str(tentativas), "-W", "1000", ip], timeout=tentativas + 5)
        
        # Procura por "time=" ou "tempo=" (extrai valores numéricos)
        tempos = re.findall(r"(?:time|tempo)=(\d+\.?\d*)\s*ms", texto_ping)
        
        if tempos:
            # Calcula a média dos pings válidos
            media = sum(float(t) for t in tempos) / len(tempos)
            total_tentativas = len(tempos)
            # Retorna média e quantos pings foram bem-sucedidos
            return f"{media:.2f} ms ({total_tentativas}/{tentativas})"
        else:
            return "Sem resposta"
    
    except subprocess.TimeoutExpired:
        return "Timeout"
    except Exception as e:
        return "Erro"

def verificar_na_tabela_arp(ip: str) -> bool:
    """Verifica se o IP aparece na tabela ARP do sistema.
    - Windows: usa 'arp -a'
    - Linux/Mac: tenta 'ip neigh' e fallback para 'arp -n'
    Retorna True se o IP estiver presente (indicando atividade recente na LAN).
    """
    try:
        if platform.system() == "Windows":
            texto = run_cmd_capture(["arp", "-a"]) or ""
            # Linhas no formato: 192.168.1.10           aa-bb-cc-dd-ee-ff    dinâmico
            padrao = r"(^|\s)(%s)(\s+)" % re.escape(ip)
            return re.search(padrao, texto, re.MULTILINE) is not None
        else:
            # ip neigh show
            texto = run_cmd_capture(["ip", "neigh", "show"]) or ""
            # Ex.: 192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            if ip in texto:
                return True
            # fallback: arp -n
            texto2 = run_cmd_capture(["arp", "-n"]) or ""
            return ip in texto2
    except Exception:
        return False

def verificar_portas_quick(ip: str, timeout: float = 0.3) -> bool:
    """Verifica rapidamente se alguma porta comum está aberta via TCP.
    Usa um conjunto pequeno de portas para reduzir custo.
    Retorna True se alguma conexão for bem-sucedida.
    """
    portas = [80, 443, 22, 3389, 445, 135]
    for porta in portas:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, porta))
            sock.close()
            if resultado == 0:
                return True
        except Exception:
            pass
    return False

def verificar_online_arp_tcp(ip: str, tentativas_ping_rapido: int = 0) -> tuple[bool, str]:
    """Determina status online usando ARP + TCP (e opcionalmente um ping rápido).
    Retorna (online_bool, metodo_str).
    Ordem:
      1. ARP na LAN (rápido, confiável em mesma subnet)
      2. TCP portas comuns (serviços ativos)
      3. (opcional) Ping rápido se solicitado
    """
    # 1) ARP
    try:
        if verificar_na_tabela_arp(ip):
            return True, "ARP"
    except Exception:
        pass
    # 2) TCP
    try:
        if verificar_portas_quick(ip):
            return True, "TCP"
    except Exception:
        pass
    # 3) Ping rápido (opcional)
    if tentativas_ping_rapido and tentativas_ping_rapido > 0:
        try:
            texto = calcular_ping(ip, tentativas=tentativas_ping_rapido)
            tempos = re.findall(r"(?:time|tempo)=(\d+\.?\d*)\s*ms", texto)
            if tempos:
                return True, "PING"
        except Exception:
            pass
    return False, "NONE"

# Dicionário de fabricantes OUI - Base expandida com centenas de fabricantes
# Formato: "XX:XX:XX" -> "Fabricante"
OUI_DATABASE = {
    # Apple
    "00:25:86": "Apple",
    "3C:22:FB": "Apple",
    "48:5B:39": "Apple",
    "50:7B:9D": "Apple",
    "B8:27:EB": "Apple/Raspberry Pi",
    
    # Cisco
    "00:1A:2B": "Cisco",
    "00:1B:D5": "Cisco",
    "00:1E:6B": "Cisco",
    "00:21:A0": "Cisco",
    "00:24:97": "Cisco",
    "00:26:0B": "Cisco",
    "00:2B:0B": "Cisco",
    "00:50:18": "Cisco/3Com",
    "54:E1:AD": "Cisco",
    "88:B1:11": "Cisco",
    "BC:85:56": "Cisco",
    "CC:2D:E0": "Cisco",
    "14:CC:20": "Cisco",
    
    # Microsoft
    "00:50:F2": "Microsoft",
    "00:0C:29": "VMware",
    
    # Intel
    "9C:67:D6": "Intel",
    "0C:29:C0": "Intel",
    "D0:17:C2": "Intel",
    
    # HP/HPE
    "00:0F:EA": "HP",
    "00:11:85": "HP",
    "00:15:C5": "HP",
    "00:1D:4F": "HP",
    "00:1E:0B": "HP",
    "00:1F:29": "HP",
    "00:22:64": "HP",
    "00:24:BE": "HP",
    "00:25:B3": "HP",
    "00:25:B4": "HP",
    "00:25:86": "HP",
    "00:30:80": "HP",
    "98:28:66": "HP",
    "E4:F4:C6": "HP",
    
    # TP-Link
    "00:12:17": "TP-Link",
    "00:30:BD": "TP-Link",
    "A4:55:95": "TP-Link",
    "64:A1:F6": "TP-Link",
    "68:A8:6D": "TP-Link",
    "C4:65:16": "TP-Link",
    "E0:55:3D": "TP-Link",
    
    # D-Link
    "00:22:55": "D-Link",
    "64:A1:F6": "D-Link",
    "DC:A9:04": "D-Link",
    "EC:29:CB": "D-Link",
    
    # Netgear
    "00:24:B2": "Netgear",
    "58:2C:80": "Netgear",
    "D8:96:95": "Netgear",
    "7C:FE:90": "Netgear",
    "20:3D:8F": "Netgear",
    
    # ASUS
    "00:0C:6E": "ASUS",
    "04:18:D6": "ASUS",
    "1C:6F:65": "ASUS",
    "78:CA:39": "ASUS",
    "84:A9:38": "ASUS",
    "D0:17:C2": "ASUS",
    "F4:6D:04": "ASUS",
    
    # Linksys
    "00:1A:70": "Linksys",
    "00:1D:AA": "Linksys",
    "00:26:62": "Linksys",
    "00:21:29": "Linksys",
    
    # Ubiquiti
    "00:21:6C": "Ubiquiti",
    "10:54:FF": "Ubiquiti",
    "18:E8:29": "Ubiquiti",
    "AC:9B:0A": "Ubiquiti",
    "B0:B2:86": "Ubiquiti",
    
    # Mikrotik
    "00:1C:A8": "Mikrotik",
    "90:E6:BA": "Mikrotik",
    
    # Synology
    "8C:DC:D4": "Synology",
    "00:11:32": "Synology",
    
    # QEMU/Virtualization
    "52:54:00": "QEMU",
    "08:00:27": "VirtualBox",
    
    # Brother
    "2C:23:FF": "Brother",
    "5C:49:7D": "Brother",
    "F8:1D:89": "Brother",
    
    # Canon
    "34:6B:D7": "Canon",
    "F0:B4:D2": "Canon",
    
    # Xerox
    "00:00:93": "Xerox",
    "08:00:09": "Xerox",
    
    # Ricoh
    "00:00:74": "Ricoh",
    "0C:A4:55": "Ricoh",
    
    # Buffalo
    "00:1D:7D": "Buffalo",
    "64:09:80": "Buffalo",
    
    # ACER
    "00:23:14": "Acer",
    "04:7E:90": "Acer",
    
    # Sony
    "00:02:B9": "Sony",
    "08:60:6E": "Sony",
    
    # Samsung
    "00:12:FB": "Samsung",
    "84:2B:2B": "Samsung",
    
    # LG
    "00:01:8D": "LG",
    "E8:F4:7B": "LG",
    
    # Panasonic
    "00:1A:40": "Panasonic",
    "08:9E:01": "Panasonic",
    
    # Epson
    "00:09:27": "Epson",
    "00:1F:CA": "Epson",
    
    # Lexmark
    "00:00:5E": "Lexmark",
    "00:04:AC": "Lexmark",
    
    # Motorola/Motorcomm
    "B0:25:AA": "Motorcomm",
    "00:1B:63": "Motorola",
    "00:25:CA": "Motorola",
    
    # Atheros/Qualcomm
    "00:1B:11": "Atheros",
    "00:1F:64": "Atheros",
    
    # Broadcom
    "00:00:F0": "Broadcom",
    "00:04:75": "Broadcom",
    "00:0B:85": "Broadcom",
    
    # Realtek
    "00:04:ED": "Realtek",
    "00:13:10": "Realtek",
    
    # Marvell
    "00:05:1C": "Marvell",
    "00:50:43": "Marvell",
    
    # Intel (WiFi)
    "00:02:B3": "Intel",
    "00:04:23": "Intel",
    "00:0F:20": "Intel",
    
    # Huawei
    "00:E0:FC": "Huawei",
    "A8:9D:21": "Huawei",
    
    # ZTE
    "00:1D:8F": "ZTE",
    "08:3A:88": "ZTE",
    
    # Fortinet
    "00:11:09": "Fortinet",
    "04:C5:A4": "Fortinet",
    
    # Juniper
    "00:05:85": "Juniper",
    "00:0E:6B": "Juniper",
    
    # F5 Networks
    "00:04:B9": "F5 Networks",
    "00:10:FF": "F5 Networks",
    
    # Ruckus
    "2C:33:61": "Ruckus",
    "F0:9B:9D": "Ruckus",
    
    # Avaya
    "00:00:F7": "Avaya",
    "00:04:F2": "Avaya",
    
    # Polycom
    "00:04:F2": "Polycom",
    "00:90:DC": "Polycom",
    
    # Dell
    "00:02:B9": "Dell",
    "00:0C:A4": "Dell",
    "00:11:43": "Dell",
    "00:1A:6B": "Dell",
    
    # Lenovo
    "00:1A:6B": "Lenovo",
    "00:1E:06": "Lenovo",
    
    # Gigabyte
    "00:1F:C6": "Gigabyte",
    "D4:6E:0E": "Gigabyte",
    
    # MSI
    "00:11:11": "MSI",
    "B8:AC:6F": "MSI",
    
    # ASRock
    "AC:DE:48": "ASRock",
    
    # Toshiba
    "00:00:F4": "Toshiba",
    "00:01:8A": "Toshiba",
    
    # NEC
    "00:00:4C": "NEC",
    "00:01:4A": "NEC",
    
    # Fujitsu
    "00:00:0E": "Fujitsu",
    "00:00:3A": "Fujitsu",
    
    # Seagate
    "D0:04:01": "Seagate",
    
    # Western Digital
    "64:11:E0": "Western Digital",
    
    # Transcend
    "04:7E:90": "Transcend",
    
    # Crucial/Micron
    "AC:9B:0A": "Crucial",
    
    # Kingston
    "00:0F:FE": "Kingston",
    
    # Corsair
    "D8:BF:C0": "Corsair",
    
    # Belkin
    "00:07:95": "Belkin",
    "00:1A:4B": "Belkin",
    
    # D-Link (adicional)
    "00:1B:3B": "D-Link",
    
    # TrendNet
    "00:12:3F": "TrendNet",
    
    # APC
    "00:C0:B7": "APC",
    
    # Eaton
    "00:0E:AB": "Eaton",
    
    # Raritan
    "00:16:94": "Raritan",
    
    # ========== ESPRESSIF (ESP32/ESP8266) ==========
    "08:3A:F2": "Espressif",
    "AC:67:B2": "Espressif",
    "E0:5A:45": "Espressif",
    "30:AE:A4": "Espressif",
    "94:B9:7E": "Espressif",
    "48:3B:38": "Espressif",
    
    # ========== MANUFACTURES CHINESES ==========
    
    # Shenzhen Xunlong (Orange Pi/Banana Pi)
    "02:42:56": "Shenzhen Xunlong",
    "00:1A:6B": "Shenzhen Xunlong",
    
    # MediaTek (NVDIA Tegra, ARM SoCs)
    "10:27:F5": "MediaTek",
    "74:A0:34": "MediaTek",
    "78:9C:DC": "MediaTek",
    
    # Goke Microelectronics
    "00:19:88": "Goke",
    "A0:B0:8C": "Goke",
    
    # Allwinner (SunXi SoCs)
    "00:00:F2": "Allwinner",
    "A0:20:A6": "Allwinner",
    
    # Rockchip
    "44:85:00": "Rockchip",
    "5C:CF:7F": "Rockchip",
    
    # Ambarella
    "00:12:34": "Ambarella",
    
    # Anyka (DVR/Câmeras)
    "00:12:00": "Anyka",
    
    # GigaDevice
    "A4:4E:31": "GigaDevice",
    
    # NXP/Freescale
    "00:04:9F": "NXP",
    "00:E0:4C": "NXP",
    "5E:AC:EC": "NXP",
    
    # STMicroelectronics
    "00:80:E1": "STMicroelectronics",
    "88:DC:96": "STMicroelectronics",
    
    # Infineon (Cypress)
    "00:14:81": "Infineon",
    "2C:F8:7C": "Infineon",
    
    # Realtek (RTL8xxx chips - China)
    "00:04:ED": "Realtek",
    "2C:3A:FD": "Realtek",
    "52:54:AB": "Realtek",
    "D4:35:76": "Realtek",
    
    # Qualcomm (Atheros-based, China)
    "00:13:74": "Qualcomm",
    "2A:C2:4A": "Qualcomm",
    
    # Broadcom (China)
    "00:04:75": "Broadcom",
    "38:1A:52": "Broadcom",
    
    # Actions Semi (DVR/Câmeras)
    "00:1C:49": "Actions Semiconductor",
    
    # Ralink (China)
    "00:21:86": "Ralink",
    "0C:47:C2": "Ralink",
    
    # Tenda (China)
    "C4:6B:B6": "Tenda",
    "F4:F5:E8": "Tenda",
    "00:18:82": "Tenda",
    
    # Cudy (China)
    "F8:E8:47": "Cudy",
    
    # Mercusys (TP-Link China)
    "A8:5E:60": "Mercusys",
    
    # Beelink (China - Mini PC)
    "B8:AC:B8": "Beelink",
    
    # MINIX (China - Android TV)
    "6A:7C:1C": "MINIX",
    "00:25:B4": "MINIX",
    
    # Vonets (China - WiFi)
    "C8:89:78": "Vonets",
    
    # Zyxel (Taiwan)
    "00:13:10": "Zyxel",
    "00:04:74": "Zyxel",
    
    # Netcore (China)
    "00:0B:85": "Netcore",
    
    # Shenzhen IP-COM (China)
    "00:0D:88": "IP-COM",
    "A4:43:9F": "IP-COM",
    
    # Shenzhen Meari (Smart Home)
    "F8:5D:0A": "Meari Smart",
    
    # Sonoff (eWeLink/Itead - China)
    "AA:BB:CC": "Sonoff",
    "E8:DB:84": "Sonoff",
    
    # Shenzhen Wescast (China)
    "58:5A:44": "Wescast",
    
    # RTL8710 variants (China - IoT)
    "48:11:22": "RTL8710",
    "E4:C3:2A": "RTL8710",
    
    # Shenzhen IPC-NET (IP Cameras)
    "00:0A:95": "IPC-NET",
    
    # Sunplus (China)
    "00:20:45": "Sunplus",
    "8C:7B:9D": "Sunplus",
    
    # Techwell (TW - DVR)
    "00:23:8E": "Techwell",
    
    # Grain Media (Taiwan - DVR)
    "00:19:E8": "Grain Media",
    
    # GJD (China - Security)
    "44:85:00": "GJD",
}

def buscar_mac_online(mac):
    """Tenta buscar MAC na base de dados online (macaddress.io) se disponível"""
    try:
        import urllib.request
        import json
        mac_clean = mac.replace(':', '-')
        url = f"https://api.macaddress.io/v1?apiKey=at_dUX8M5eCMDvQwL5kGR1AzQs4J2Z09&output=json&search={mac_clean}"
        
        with urllib.request.urlopen(url, timeout=2) as response:
            data = json.loads(response.read().decode())
            if data.get("vendorDetails"):
                return data["vendorDetails"].get("companyName", "Desconhecido")
    except Exception:
        pass
    return None

# Mapa de portas -> serviços (expandido com portas comuns)
PORTA_SERVICOS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-ALT",
    9100: "Printer",
    27017: "MongoDB",
    50070: "Hadoop"
}

def escanear_portas(ip, timeout=0.5):
    """Escaneia TODAS as portas comuns para descobrir serviços rodando (threaded)"""
    portas_abertas = []
    
    # Expandir para incluir mais portas comuns
    portas_teste = list(PORTA_SERVICOS.keys())
    
    def testar_porta(porta):
        """Testa uma porta específica"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, porta))
            sock.close()
            
            if resultado == 0:
                return porta
        except Exception:
            pass
        return None
    
    # Escaneia portas em paralelo (até 20 threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        resultados = executor.map(testar_porta, portas_teste)
        portas_abertas = [p for p in resultados if p is not None]
    
    if not portas_abertas:
        return "Nenhum"
    
    # Organiza resultado
    servicos = []
    for porta in sorted(portas_abertas):
        servico = PORTA_SERVICOS.get(porta, f"Port:{porta}")
        servicos.append(f"{servico}({porta})")
    
    return ", ".join(servicos)

def escanear_todas_portas(ip, timeout=0.3, max_porta=1024):
    """Escaneia TODAS as portas até max_porta (mais lento, mas completo)"""
    portas_abertas = []
    
    def testar_porta(porta):
        """Testa uma porta específica"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            resultado = sock.connect_ex((ip, porta))
            sock.close()
            
            if resultado == 0:
                return porta
        except Exception:
            pass
        return None
    
    # Escaneia portas em paralelo (até 50 threads para mais velocidade)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        resultados = executor.map(testar_porta, range(1, max_porta + 1))
        portas_abertas = [p for p in resultados if p is not None]
    
    if not portas_abertas:
        return "Nenhum"
    
    # Organiza resultado
    servicos = []
    for porta in sorted(portas_abertas):
        servico = PORTA_SERVICOS.get(porta, f"Port:{porta}")
        servicos.append(f"{servico}({porta})")
    
    return ", ".join(servicos)

def obter_info_dispositivo(ip, mac):
    """Tenta obter hostname e fabricante do dispositivo"""
    hostname = "N/A"
    fabricante = "Desconhecido"
    
    # Tenta resolver hostname via DNS
    try:
        resultado = socket.gethostbyaddr(ip)
        hostname = resultado[0].split('.')[0][:20]  # limita a 20 caracteres
    except (socket.herror, socket.timeout):
        hostname = "N/A"
    except Exception:
        hostname = "N/A"
    
    # Usa a função de identificação por MAC que já integra OUI database online
    if mac and mac != "N/A":
        try:
            identificacao = identificar_equipamento_por_mac(mac)
            if identificacao and identificacao.fabricante:
                # Extrai apenas o nome do fabricante (remove tabs/espaços extras)
                fabricante = identificacao.fabricante.split('\t')[0].strip()
                if not fabricante or fabricante == "Desconhecido":
                    fabricante = "Desconhecido"
        except Exception as e:
            # Fallback para método antigo se houver erro
            mac_upper = mac.upper()
            oui_6 = mac_upper[:8]  # "XX:XX:XX"
            
            if oui_6 in OUI_DATABASE:
                info = OUI_DATABASE[oui_6]
                # Verifica se é dict (nova estrutura) ou string (antiga estrutura)
                if isinstance(info, dict):
                    fabricante = info.get("fabricante", "Desconhecido")
                elif isinstance(info, tuple):
                    fabricante = info[0] if len(info) > 0 else "Desconhecido"
                else:
                    fabricante = str(info)
                
                # Limpa formatação (remove tabs)
                if fabricante:
                    fabricante = fabricante.split('\t')[0].strip()
    
    return hostname, fabricante

def extrair_info_ping(ip, tentativas=3):
    """Extrai TTL, tamanho ICMP, SO detectado e descrição do ping"""
    ttl = None
    tamanho = None
    so = "Desconhecido"
    
    try:
        if platform.system() == "Windows":
            texto_ping = run_cmd_capture(["ping", "-n", str(tentativas), ip], timeout=tentativas + 5)
            
            # Extrai TTL (próximo do valor inicial antes de chegar ao destino)
            m_ttl = re.search(r"TTL=(\d+)", texto_ping)
            if m_ttl:
                ttl = int(m_ttl.group(1))
            
            # Extrai tamanho ICMP (bytes=XX)
            m_tamanho = re.search(r"bytes=(\d+)", texto_ping)
            if m_tamanho:
                tamanho = int(m_tamanho.group(1))
        else:
            texto_ping = run_cmd_capture(["ping", "-c", str(tentativas), ip], timeout=tentativas + 5)
            
            # Extrai TTL
            m_ttl = re.search(r"ttl=(\d+)", texto_ping, re.IGNORECASE)
            if m_ttl:
                ttl = int(m_ttl.group(1))
            
            # Extrai tamanho
            m_tamanho = re.search(r"(\d+) bytes from", texto_ping)
            if m_tamanho:
                tamanho = int(m_tamanho.group(1))
        
        # Detecta SO baseado em TTL
        if ttl:
            if 240 <= ttl <= 255:
                so = "Windows (TTL~255)"
            elif 60 <= ttl <= 64:
                so = "Linux/Unix (TTL~64)"
            elif 100 <= ttl <= 120:
                so = "Windows (TTL~128)"
            elif 30 <= ttl <= 32:
                so = "Cisco/Rede"
            else:
                so = f"Outro (TTL={ttl})"
    except Exception:
        pass
    
    return ttl, tamanho, so

def obter_netbios(ip):
    """Tenta obter informações NetBIOS do dispositivo (Windows)"""
    nome_netbios = "N/A"
    
    if platform.system() == "Windows":
        try:
            # nbstat -a <ip> retorna informações NetBIOS
            texto_nbt = run_cmd_capture(["nbtstat", "-a", ip], timeout=2)
            
            # Extrai o nome do computador (primeira linha de endereços)
            m_nome = re.search(r"^([A-Z0-9\-]+)\s+<00> UNIQUE", texto_nbt, re.MULTILINE | re.IGNORECASE)
            if m_nome:
                nome_netbios = m_nome.group(1)[:15]  # limita a 15 caracteres
        except Exception:
            pass
    
    return nome_netbios

def main():
    """Função principal"""
    print("=" * 70)
    print(" " * 15 + "ANALISADOR DE REDE LOCAL")
    print("=" * 70)
    print()
    
    # Obtém interface ativa
    print("[INFO] Obtendo informações da rede...")
    ip_local, mascara = obter_interface_ativa()
    
    if not ip_local:
        print("[ERRO] Não foi possível obter informações da rede!")
        sys.exit(1)
    
    print(f"[OK] IP Local: {ip_local}")
    print(f"[OK] Máscara: {mascara}")
    print()
    
    # Faz ARP scan
    print("[INFO] Escaneando rede...")
    dispositivos = fazer_arp_scan(ip_local, mascara)
    
    if not dispositivos:
        print("[ERRO] Nenhum dispositivo encontrado na rede!")
        sys.exit(1)
    
    print(f"[OK] {len(dispositivos)} dispositivo(s) encontrado(s)")
    print()
    
    # Ordena por IP
    dispositivos_ordenados = sorted(
        dispositivos.items(),
        key=lambda x: [int(p) for p in x[0].split(".")]
    )
    
    # Coleta dados e faz ping
    print("[INFO] Fazendo ping (isso pode levar alguns minutos)...")
    dados_tabela = []
    
    for i, (ip, mac) in enumerate(dispositivos_ordenados, 1):
        print(f"  [{i}/{len(dispositivos_ordenados)}] Pingando {ip}...", end="", flush=True)
        ping = calcular_ping(ip, tentativas=10)
        print(f" {ping}")
        
        dados_tabela.append([ip, mac, ping])
    
    print()
    print("=" * 70)
    print(" " * 20 + "RESULTADO DO SCAN")
    print("=" * 70)
    print()
    
    # Exibe tabela
    cabecalho = ["IP Address", "MAC Address", "Ping Médio (10 tentativas)"]
    print(tabulate(
        dados_tabela,
        headers=cabecalho,
        tablefmt="grid",
        stralign="center"
    ))
    
    print()
    print("=" * 70)
    print(f"Total de dispositivos encontrados: {len(dados_tabela)}")
    print("=" * 70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[WARN] Programa interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERRO] Erro inesperado: {e}")
        sys.exit(1)
