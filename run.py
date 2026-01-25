#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ANALISADOR DE REDE v2.2
Launcher Principal - Inicia a Interface Gráfica
"""

import sys
import os

# Adiciona diretório ao path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

def main():
    try:
        # Importa módulos necessários
        import tkinter as tk
        from analisador_rede_gui import NetworkAnalyzerApp
        
        # Cria janela principal
        root = tk.Tk()
        root.protocol("WM_DELETE_WINDOW", lambda: root.quit())
        
        # Cria aplicação
        app = NetworkAnalyzerApp(root)
        
        # Inicia loop principal
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\n\nAplicação encerrada pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\nERRO NA APLICACAO: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
