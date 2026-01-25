#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TESTE: Identificação de Equipamento por MAC Address
═══════════════════════════════════════════════════════════════════════════

Demonstra o funcionamento da função identificar_equipamento_por_mac()
que identifica o nome provável e tipo de equipamento a partir do MAC.
"""

import sys
import os

# Adiciona diretório ao path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from analisador_rede import identificar_equipamento_por_mac, identificar_multiplos_equipamentos
import json


def teste_individual():
    """Testa identificação de equipamentos individuais"""
    print("=" * 80)
    print(" TESTE 1: IDENTIFICAÇÃO INDIVIDUAL POR MAC")
    print("=" * 80)
    print()
    
    # Lista de MACs para testar
    macs_teste = [
        "24:4B:03:AA:BB:CC",  # Espressif ESP8266/ESP32
        "00:1A:7D:BB:CC:DD",  # Samsung
        "00:1F:F3:11:22:33",  # Apple
        "14:CC:20:44:55:66",  # Amazon Echo
        "00:0F:33:77:88:99",  # Arcadyan (Roteador)
        "1C:BD:B9:AA:BB:CC",  # TP-Link
        "30:F1:12:34:56:78",  # Hikvision Câmera
        "00:09:6B:AA:BB:CC",  # HP Impressora
        "00:11:32:CC:DD:EE",  # Synology NAS
        "FF:FF:FF:FF:FF:FF",  # MAC Inválido
        "00:00:00:00:00:00",  # MAC genérico/desconhecido
    ]
    
    for mac in macs_teste:
        print(f"\nTestando MAC: {mac}")
        print("-" * 80)
        
        resultado = identificar_equipamento_por_mac(mac)
        
        print(f"  OUI:                {resultado.oui}")
        print(f"  Fabricante:         {resultado.fabricante}")
        print(f"  Tipo de Equipamento:{resultado.tipo_equipamento}")
        print(f"  Confiança:          {resultado.confianca}")
        print(f"  String Formatada:   {resultado}")
        
        # Exibe como dicionário (para serialização JSON)
        print(f"\n  Dicionário (JSON-ready):")
        print(f"  {json.dumps(resultado.to_dict(), indent=4, ensure_ascii=False)}")


def teste_multiplo():
    """Testa identificação de múltiplos equipamentos"""
    print("\n\n")
    print("=" * 80)
    print(" TESTE 2: IDENTIFICAÇÃO MÚLTIPLA (Dicionário IP:MAC)")
    print("=" * 80)
    print()
    
    # Simula uma rede com vários dispositivos
    dispositivos = {
        "192.168.1.1": "00:0F:33:77:88:99",    # Arcadyan Router
        "192.168.1.10": "24:4B:03:AA:BB:CC",   # ESP32 IoT
        "192.168.1.20": "00:1A:7D:BB:CC:DD",   # Samsung Smartphone
        "192.168.1.30": "00:1F:F3:11:22:33",   # Apple iPhone
        "192.168.1.50": "14:CC:20:44:55:66",   # Amazon Echo
        "192.168.1.100": "00:09:6B:AA:BB:CC",  # HP Impressora
        "192.168.1.200": "00:11:32:CC:DD:EE",  # Synology NAS
    }
    
    print(f"Analisando {len(dispositivos)} dispositivos...\n")
    
    resultados = identificar_multiplos_equipamentos(dispositivos)
    
    # Exibe em formato tabular
    print(f"{'IP':<15} {'Fabricante':<20} {'Tipo de Equipamento':<40} {'Confiança':<10}")
    print("-" * 85)
    
    for ip in sorted(dispositivos.keys()):
        info = resultados[ip]
        print(f"{ip:<15} {info.fabricante:<20} {info.tipo_equipamento:<40} {info.confianca:<10}")


def teste_casos_especiais():
    """Testa casos especiais e tratamento de erros"""
    print("\n\n")
    print("=" * 80)
    print(" TESTE 3: CASOS ESPECIAIS E TRATAMENTO DE ERROS")
    print("=" * 80)
    print()
    
    casos_especiais = [
        ("24:4B:03:AA:BB:CC", "MAC com dois-pontos (padrão)"),
        ("244B03AABBCC", "MAC sem formatação"),
        ("24-4B-03-AA-BB-CC", "MAC com hífens"),
        ("24 4B 03 AA BB CC", "MAC com espaços"),
        ("244B03aabbcc", "MAC em minúsculas"),
        ("INVALID", "MAC inválido"),
        ("00:00:00:00:00", "MAC incompleto"),
        ("00:11:22:33:44:55:66", "MAC muito longo"),
    ]
    
    for mac, descricao in casos_especiais:
        print(f"\nTestando: {descricao}")
        print(f"  Entrada: '{mac}'")
        print("-" * 80)
        
        try:
            resultado = identificar_equipamento_por_mac(mac)
            print(f"  OUI:                {resultado.oui}")
            print(f"  Fabricante:         {resultado.fabricante}")
            print(f"  Tipo:               {resultado.tipo_equipamento}")
            print(f"  Confiança:          {resultado.confianca}")
        except Exception as e:
            print(f"  ERRO: {e}")


def teste_heuristicas():
    """Demonstra as regras heurísticas em ação"""
    print("\n\n")
    print("=" * 80)
    print(" TESTE 4: DEMONSTRAÇÃO DE HEURÍSTICAS")
    print("=" * 80)
    print()
    
    print("""
As heurísticas refinam a identificação baseando-se no fabricante:

EXEMPLOS:
  - Espressif         → ESP8266/ESP32 - Sonoff/IoT/Sensor WiFi
  - Apple             → iPhone/iPad/MacBook/Apple TV
  - Amazon            → Amazon Echo/Alexa/Fire TV
  - Arcadyan          → Roteador/Modem/ONT de Operadora
  - Hikvision         → Câmera IP/NVR Hikvision
  - HP                → Impressora/Multifuncional HP
  - Synology          → Synology NAS - Network Storage
  - TP-Link           → TP-Link Roteador/Switch/WiFi
  - Cisco             → Cisco Roteador/Switch/Equipamento Profissional
    """)
    
    print("\nTestando com exemplos reais:")
    
    # Testa um Espressif ESP32 (Sonoff)
    print("\n1. Espressif (Sonoff):")
    resultado = identificar_equipamento_por_mac("24:4B:03:AA:BB:CC")
    print(f"   Fabricante: {resultado.fabricante}")
    print(f"   Tipo: {resultado.tipo_equipamento}")
    print(f"   Confiança: {resultado.confianca}")
    
    # Testa um Apple iPhone
    print("\n2. Apple iPhone:")
    resultado = identificar_equipamento_por_mac("00:1F:F3:11:22:33")
    print(f"   Fabricante: {resultado.fabricante}")
    print(f"   Tipo: {resultado.tipo_equipamento}")
    print(f"   Confiança: {resultado.confianca}")
    
    # Testa uma Câmera Hikvision
    print("\n3. Hikvision Câmera:")
    resultado = identificar_equipamento_por_mac("30:F1:12:34:56:78")
    print(f"   Fabricante: {resultado.fabricante}")
    print(f"   Tipo: {resultado.tipo_equipamento}")
    print(f"   Confiança: {resultado.confianca}")


def teste_stats():
    """Exibe estatísticas do banco de dados"""
    print("\n\n")
    print("=" * 80)
    print(" TESTE 5: ESTATÍSTICAS DO BANCO DE DADOS")
    print("=" * 80)
    print()
    
    from analisador_rede import OUI_DATABASE
    
    print(f"Total de OUIs cadastrados: {len(OUI_DATABASE)}")
    
    # Agrupa por fabricante
    fabricantes = {}
    for oui, (fab, tipo) in OUI_DATABASE.items():
        if fab not in fabricantes:
            fabricantes[fab] = 0
        fabricantes[fab] += 1
    
    print(f"\nTotal de fabricantes únicos: {len(fabricantes)}")
    print("\nFabricantes mais comuns:")
    
    for fab, count in sorted(fabricantes.items(), key=lambda x: -x[1])[:15]:
        print(f"  {fab:<30} {count:>2} OUI(s)")


def menu_principal():
    """Menu interativo"""
    while True:
        print("\n" + "=" * 80)
        print(" TESTE DE IDENTIFICAÇÃO POR MAC - MENU")
        print("=" * 80)
        print("""
1. Testes básicos (individual)
2. Testes com múltiplos equipamentos
3. Casos especiais e erros
4. Demonstração de heurísticas
5. Estatísticas do banco de dados
6. Executar todos os testes
0. Sair
        """)
        
        escolha = input("Escolha uma opção (0-6): ").strip()
        
        if escolha == "1":
            teste_individual()
        elif escolha == "2":
            teste_multiplo()
        elif escolha == "3":
            teste_casos_especiais()
        elif escolha == "4":
            teste_heuristicas()
        elif escolha == "5":
            teste_stats()
        elif escolha == "6":
            teste_individual()
            teste_multiplo()
            teste_casos_especiais()
            teste_heuristicas()
            teste_stats()
        elif escolha == "0":
            print("\nEncerrando...")
            break
        else:
            print("\nOpcao invalida!")
        
        input("\nPressione ENTER para continuar...")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Modo CLI: executa todos os testes
        print("Modo batch: Executando todos os testes...\n")
        teste_individual()
        teste_multiplo()
        teste_casos_especiais()
        teste_heuristicas()
        teste_stats()
        print("\n" + "=" * 80)
        print("Testes concluídos!")
        print("=" * 80)
    else:
        # Modo interativo
        try:
            menu_principal()
        except KeyboardInterrupt:
            print("\n\nPrograma interrompido pelo usuário.")
            sys.exit(0)
