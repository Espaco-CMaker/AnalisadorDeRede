#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Script de teste - Força exibição de erros da GUI"""

import sys
import os
import traceback

sys.path.insert(0, r'd:\+Espaço CMaker\Projetos\#2026\AnalisadorDeRede')

print("=" * 70)
print("TESTE DE INTERFACE GRAFICA - Diagnostico Completo")
print("=" * 70)

try:
    print("\n[1] Importando tkinter...")
    import tkinter as tk
    from tkinter import ttk
    print("    OK")
    
    print("[2] Importando matplotlib...")
    import matplotlib
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    print("    OK")
    
    print("[3] Importando analisador_rede...")
    from analisador_rede import fazer_arp_scan
    print("    OK")
    
    print("[4] Importando analisador_rede_gui...")
    from analisador_rede_gui import NetworkAnalyzerApp
    print("    OK")
    
    print("[5] Criando janela Tkinter...")
    root = tk.Tk()
    root.geometry("100x100")
    print("    OK - Janela criada")
    
    print("[6] Instanciando NetworkAnalyzerApp...")
    app = NetworkAnalyzerApp(root)
    print("    OK - App criada")
    
    print("[7] Iniciando mainloop...")
    print("\n    Se voce vir uma janela, o problema foi resolvido!")
    print("    Se nao aparecer nada, feche este script.\n")
    
    root.mainloop()
    
    print("\nSucesso! Interface funciona.")
    sys.exit(0)
    
except Exception as e:
    print(f"\n\nERRO DETECTADO:")
    print(f"Tipo: {type(e).__name__}")
    print(f"Mensagem: {e}")
    print("\nRastreamento completo:")
    print("=" * 70)
    traceback.print_exc()
    print("=" * 70)
    sys.exit(1)
