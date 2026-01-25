#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Launcher com diagnóstico para Analisador de Rede
"""

import sys
import os
import traceback

# Adiciona o diretório ao path
diretorio = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, diretorio)

print("=" * 70)
print("ANALISADOR DE REDE v2.1 - Launcher com Diagnóstico")
print("=" * 70)

try:
    print("\n[1] Verificando ambiente Python...")
    print(f"    Versão: {sys.version.split()[0]}")
    print(f"    Diretório: {diretorio}")
    
    print("\n[2] Importando módulos...")
    import tkinter as tk
    print("    - tkinter: OK")
    
    from analisador_rede import fazer_arp_scan
    print("    - analisador_rede: OK")
    
    import matplotlib
    print("    - matplotlib: OK")
    
    import numpy
    print("    - numpy: OK")
    
    print("\n[3] Importando interface gráfica...")
    from analisador_rede_gui import NetworkAnalyzerApp
    print("    - analisador_rede_gui: OK")
    
    print("\n[4] Criando aplicação...")
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    print("    - NetworkAnalyzerApp: OK")
    
    print("\n[5] Iniciando loop principal...")
    print("\n" + "=" * 70)
    print("Interface gráfica aberta com sucesso!")
    print("Feche a janela para encerrar.")
    print("=" * 70 + "\n")
    
    root.mainloop()
    
    print("\nAplicação encerrada com sucesso.")
    sys.exit(0)
    
except Exception as e:
    print("\n" + "=" * 70)
    print("ERRO DETECTADO!")
    print("=" * 70)
    print(f"\nTipo: {type(e).__name__}")
    print(f"Mensagem: {e}")
    print("\nRastreamento completo:")
    print("-" * 70)
    traceback.print_exc()
    print("-" * 70)
    print("\nDicas de solução:")
    print("1. Verifique se todos os módulos estão instalados")
    print("2. Tente executar: pip install -r requirements.txt")
    print("3. Se o erro persistir, abra uma issue com o rastreamento acima")
    sys.exit(1)
