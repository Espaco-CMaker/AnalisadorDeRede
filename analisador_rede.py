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
from tabulate import tabulate
from collections import defaultdict


def run_cmd_capture(cmd, timeout=None):
    """Executa um comando e retorna stdout como texto com decodificação robusta (Windows)."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
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
            
            for ip, mac in matches:
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    if ip_obj in rede:
                        dispositivos[ip] = mac.replace("-", ":")
                except:
                    pass
            
            # Se encontrou poucos, faz ping broadcast para popular ARP
            if len(dispositivos) < 3:
                print("[INFO] Descobrindo dispositivos na rede (aguarde ~30s)...")
                
                # Faz ping para endereços da rede
                for host in list(rede.hosts())[:255]:
                    ip_alvo = str(host)
                    try:
                        subprocess.run(["ping", "-n", "1", "-w", "100", ip_alvo], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
                    except:
                        pass
                
                # Re-executa arp -a
                texto_arp = run_cmd_capture(["arp", "-a"]) or ""
                matches = re.findall(padrao, texto_arp)
                dispositivos = {}
                for ip, mac in matches:
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)
                        if ip_obj in rede:
                            dispositivos[ip] = mac.replace("-", ":")
                    except:
                        pass
        
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
    
    # Tenta extrair fabricante do MAC (OUI - Organizationally Unique Identifier)
    if mac and mac != "N/A":
        mac_upper = mac.upper()
        
        # Primeiro tenta com os 6 primeiros caracteres (XX:XX:XX)
        oui_6 = mac_upper[:8]  # "XX:XX:XX"
        if oui_6 in OUI_DATABASE:
            fabricante = OUI_DATABASE[oui_6]
        else:
            # Tenta com 5 primeiros caracteres (XX:XX)
            oui_5 = mac_upper[:5]  # "XX:XX"
            for oui, brand in OUI_DATABASE.items():
                if oui.startswith(oui_5):
                    fabricante = brand
                    break
            
            # Se ainda não encontrou, tenta com 2 primeiros caracteres
            if fabricante == "Desconhecido":
                oui_2 = mac_upper[:2]
                for oui, brand in OUI_DATABASE.items():
                    if oui.startswith(oui_2):
                        fabricante = brand
                        break
            
            # Se ainda assim não encontrou, tenta buscar online (opcional)
            if fabricante == "Desconhecido":
                resultado_online = buscar_mac_online(mac)
                if resultado_online:
                    fabricante = resultado_online[:30]  # limita comprimento
    
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
