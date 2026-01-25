#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Script de teste da interface gráfica"""

import sys
import traceback

# Adiciona o diretório ao path
sys.path.insert(0, r'd:\+Espaço CMaker\Projetos\#2026\AnalisadorDeRede')

try:
    print("[1] Importando modulos base...")
    import tkinter as tk
    from tkinter import ttk
    import threading
    print("    [OK] Modulos base")
    
    print("[2] Importando analisador_rede...")
    from analisador_rede import (
        obter_interface_ativa,
        fazer_arp_scan,
        calcular_ping,
        obter_info_dispositivo,
        extrair_info_ping,
        obter_netbios,
        escanear_portas
    )
    print("    [OK] analisador_rede")
    
    print("[3] Importando matplotlib...")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import numpy as np
    print("    [OK] matplotlib")
    
    print("[4] Criando janela Tkinter...")
    root = tk.Tk()
    root.title("Teste da Interface")
    root.geometry("400x300")
    print("    [OK] Janela criada")
    
    print("[5] Adicionando widgets...")
    label = ttk.Label(root, text="Interface gráfica funcionando!")
    label.pack(pady=20)
    
    btn_sair = ttk.Button(root, text="Sair", command=root.quit)
    btn_sair.pack(pady=10)
    print("    [OK] Widgets adicionados")
    
    print("[6] Iniciando loop principal...")
    print("\nSe você vir uma janela, a interface está OK!")
    print("Feche a janela para continuar.\n")
    
    root.mainloop()
    
    print("\nTeste concluído com sucesso!")
    sys.exit(0)
    
except Exception as e:
    print(f"\nERRO DETECTADO:")
    print(f"  Tipo: {type(e).__name__}")
    print(f"  Mensagem: {e}")
    print("\nRastreamento completo:")
    traceback.print_exc()
    sys.exit(1)
