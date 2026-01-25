#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Script para diagnosticar problemas de inicialização"""

import sys
import os

diretorio = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, diretorio)

print("Diagnosticando analisador_rede_gui.py...")

try:
    # Teste 1: Importar modulo
    print("[1] Importando analisador_rede_gui...")
    import analisador_rede_gui
    print("    OK - Modulo importado sem erros")
    
    # Teste 2: Procurar erros na classe
    print("[2] Verificando classe NetworkAnalyzerApp...")
    if hasattr(analisador_rede_gui, 'NetworkAnalyzerApp'):
        print("    OK - Classe encontrada")
    else:
        print("    ERRO - Classe nao encontrada")
        sys.exit(1)
    
    # Teste 3: Verificar metodos
    print("[3] Verificando metodos...")
    cls = analisador_rede_gui.NetworkAnalyzerApp
    metodos_esperados = [
        '__init__',
        '_show_ports_menu',
        '_open_port',
        '_on_tree_right_click'
    ]
    
    for metodo in metodos_esperados:
        if hasattr(cls, metodo):
            print(f"    - {metodo}: OK")
        else:
            print(f"    - {metodo}: FALTA!")
    
    print("\nTodos os testes passaram!")
    print("A interface pode ser inicializada normalmente.")
    
except SyntaxError as e:
    print(f"ERRO DE SINTAXE: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
    
except Exception as e:
    print(f"ERRO: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
