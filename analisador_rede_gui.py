#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                     ANALISADOR DE REDE v2.0                              ║
║          Interface Gráfica - Descoberta e Monitoramento em Tempo Real    ║
╚═══════════════════════════════════════════════════════════════════════════╝

Módulo GUI: Interface Tkinter com 3 Abas
───────────────────────────────────────────────────────────────────────────

ABAS:
  1. DISPOSITIVOS: Tabela de IPs com 10 colunas + gráfico de pings
  2. CONFIGURAÇÕES: Ajustes de scan (tentativas, intervalo)
  3. LOGS: Histórico com timestamps

RECURSOS:
  ✓ Tabela interativa com ordenação por clique
  ✓ Gráfico Unicode (▁▂▃▄▅▆▇█) dos últimos 15 pings
  ✓ Destaque amarelo de linhas atualizadas
  ✓ Threading não-bloqueante (daemon thread)
  ✓ Fila segura para comunicação entre threads
  ✓ Persistência de configuração (config.json)
  ✓ Prevenção automática de duplicatas
  ✓ Scan contínuo ou único sob demanda

ESTRUTURA:
  • NetworkAnalyzerApp: Classe principal (Tkinter)
  • _do_scan(): Thread de varredura ARP
  • _add_table_item(): Insere/atualiza linhas (O(1) com dicionário)
  • _process_queue(): Processa eventos da fila

VERSÃO: 2.0
DATA: Janeiro 2026
AUTOR: CMaker Projects

───────────────────────────────────────────────────────────────────────────
"""

import threading
import time
from datetime import datetime, timedelta
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont
import json
import os
import re  # para gráfico e processamento
import webbrowser  # para abrir URLs
import csv  # para exportação CSV

# Matplotlib para gráficos profissionais
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np  # para curva de tendência

# Reutiliza funções já existentes
try:
    from analisador_rede import (
        obter_interface_ativa,
        fazer_arp_scan,
        calcular_ping,
        obter_info_dispositivo,
        extrair_info_ping,
        obter_netbios,
        escanear_portas,
        run_cmd_capture,
        verificar_online_arp_tcp,
    )
except Exception as exc:  # fallback defensivo
    raise SystemExit(f"Falha ao importar analisador_rede: {exc}")

class NetworkAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Analisador de Rede")
        self.root.geometry("1200x600")
        
        # Arquivo de configuração
        self.config_file = "config.json"

        # Estado
        self.queue: Queue = Queue()
        self.stop_event = threading.Event()
        self.scan_thread = None
        self.devices = []  # lista de dicts
        self.ping_history = {}  # {ip: [lista de pings em ms]}
        self.ping_history_lock = threading.Lock()
        self.ping_history_file = "ping_history.json"
        self.last_ping_save = 0  # epoch do último save
        self.table_ips = {}  # {ip: item_id} para rastrear IPs na tabela
        self.device_nicknames = {}  # {mac: "nome personalizado"} - apelidos persistentes
        
        # Estado de threads de dispositivos
        self.device_threads = {}  # {ip: thread object}
        self.device_lock = threading.Lock()  # protege acesso ao dicionário
        
        # IP selecionado para gráfico
        self.selected_ip = None

        # Gateway atual da rede
        self.current_gateway = "-"

        # Carrega configurações do arquivo
        config = self._load_config()
        self._load_nicknames()  # Carrega apelidos de dispositivos
        
        # Inicializa banco OUI (fabricantes) - carrega do cache local
        try:
            from analisador_rede import inicializar_oui_database
            inicializar_oui_database(atualizar_online=False)
            print("[OK] Banco OUI inicializado com sucesso")
        except Exception as e:
            print(f"[AVISO] Erro ao inicializar banco OUI: {e}")
        
        # Configurações
        self.ping_attempts = tk.IntVar(value=config.get("ping_attempts", 4))
        self.scan_interval = tk.IntVar(value=config.get("scan_interval", 60))  # segundos
        self.history_hours = tk.IntVar(value=config.get("history_hours", 24))  # horas de histórico persistente
        self.graph_sash_position = config.get("graph_sash_position", 650)  # Posição do divisor do gráfico
        
        # Rastreia alterações para salvar
        self.ping_attempts.trace("w", lambda *args: self._save_config())
        self.scan_interval.trace("w", lambda *args: self._save_config())
        self.history_hours.trace("w", lambda *args: self._on_history_hours_change())

        # Carrega histórico de ping após ter history_hours configurado
        self._load_ping_history()

        # Ordenação
        self.sort_column = None
        self.sort_reverse = False

        # UI
        self._build_ui()
        
        # Salva configuração ao fechar
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Inicia loop de processamento de fila
        self.root.after(200, self._process_queue)
        
        # Atualiza tabela de MACs periodicamente (a cada 5 segundos)
        self.root.after(5000, self._update_macs_table_periodically)

    # ------------------------------------------------------------------
    # UI
    def _build_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Abas
        self.tab_devices = ttk.Frame(notebook)
        self.tab_macs = ttk.Frame(notebook)
        self.tab_config = ttk.Frame(notebook)
        self.tab_logs = ttk.Frame(notebook)

        notebook.add(self.tab_devices, text="Dispositivos")
        notebook.add(self.tab_macs, text="MACs/Nomes")
        notebook.add(self.tab_config, text="Configurações")
        notebook.add(self.tab_logs, text="Logs")

        self._build_devices_tab()
        self._build_macs_tab()
        self._build_config_tab()
        self._build_logs_tab()

    def _build_devices_tab(self):
        top_frame = ttk.Frame(self.tab_devices)
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        self.btn_start = ttk.Button(top_frame, text="Iniciar", command=self.start_scan)
        self.btn_stop = ttk.Button(top_frame, text="Parar", command=self.stop_scan, state=tk.DISABLED)

        self.btn_start.pack(side=tk.LEFT, padx=5)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar(value="Pronto")
        ttk.Label(top_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=15)
        
        # Checkbox para filtrar apenas dispositivos online
        self.show_online_only_var = tk.BooleanVar(value=False)
        chk_online = ttk.Checkbutton(top_frame, text="Apenas online", variable=self.show_online_only_var, command=self._filter_online_only)
        chk_online.pack(side=tk.LEFT, padx=15)

        # Usa PanedWindow para permitir redimensionamento do gráfico
        self.paned_window = tk.PanedWindow(self.tab_devices, orient=tk.HORIZONTAL, sashwidth=6, sashrelief=tk.RAISED)
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Frame da tabela
        table_frame = ttk.Frame(self.paned_window)
        
        # Tabela com colunas: #, IP, MAC, Nome, Hostname, NetBIOS, Fabricante, Serviços, Ping, Histórico
        columns = ("num", "status", "ip", "mac", "nome", "hostname", "netbios", "fabricante", "servicos", "ping", "grafico", "historico")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("num", text="#", command=lambda: self._sort_table("num"))
        self.tree.heading("status", text=" ", command=lambda: self._sort_table("status"))
        self.tree.heading("ip", text="IP", command=lambda: self._sort_table("ip"))
        self.tree.heading("mac", text="MAC Address", command=lambda: self._sort_table("mac"))
        self.tree.heading("nome", text="Nome [Editar]", command=lambda: self._sort_table("nome"))
        self.tree.heading("hostname", text="Hostname", command=lambda: self._sort_table("hostname"))
        self.tree.heading("netbios", text="NetBIOS", command=lambda: self._sort_table("netbios"))
        self.tree.heading("fabricante", text="Fabricante", command=lambda: self._sort_table("fabricante"))
        self.tree.heading("servicos", text="Serviços", command=lambda: self._sort_table("servicos"))
        self.tree.heading("ping", text="Ping", command=lambda: self._sort_table("ping"))
        self.tree.heading("grafico", text="Gráfico", command=lambda: self._sort_table("grafico"))
        self.tree.heading("historico", text="Histórico", command=lambda: self._sort_table("historico"))
        
        self.tree.column("num", width=25, anchor="center")
        self.tree.column("status", width=26, anchor="center")
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("mac", width=120, anchor="center")
        self.tree.column("nome", width=130, anchor="w")  # Editável, alinhado à esquerda
        self.tree.column("hostname", width=100, anchor="center")
        self.tree.column("netbios", width=90, anchor="center")
        self.tree.column("fabricante", width=110, anchor="center")
        self.tree.column("servicos", width=120, anchor="center")
        self.tree.column("ping", width=70, anchor="center")
        self.tree.column("grafico", width=100, anchor="center")
        self.tree.column("historico", width=280, anchor="center")
        
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.configure(xscrollcommand=hsb.set)

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # Adiciona painel de gráfico à direita com matplotlib
        graph_frame = ttk.LabelFrame(self.paned_window, text="Gráfico de Ping (Clique em um IP)")
        
        # Adiciona os frames ao PanedWindow
        self.paned_window.add(table_frame, stretch="always")
        self.paned_window.add(graph_frame, stretch="never")
        
        # Restaura a posição do sash se configurada
        self.root.after(100, lambda: self._restore_sash_position())
        
        # Bind para salvar posição ao redimensionar
        self.paned_window.bind("<ButtonRelease-1>", self._on_sash_moved)
        
        # Adiciona os frames ao PanedWindow
        self.paned_window.add(table_frame, stretch="always")
        self.paned_window.add(graph_frame, stretch="never")
        
        # Restaura a posição do sash se configurada
        self.root.after(100, lambda: self._restore_sash_position())
        
        # Bind para salvar posição ao redimensionar
        self.paned_window.bind("<ButtonRelease-1>", self._on_sash_moved)
        
        # Botão para abrir no browser
        button_frame = ttk.Frame(graph_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.btn_browser = ttk.Button(button_frame, text="🌐 Abrir no Browser", 
                                      command=self._open_browser, state=tk.DISABLED)
        self.btn_browser.pack(fill=tk.X)
        
        # Cria figura matplotlib
        self.fig = Figure(figsize=(4.5, 2.8), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_facecolor('#f0f0f0')
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Variáveis para armazenar dados do gráfico para tooltip
        self.graph_data = None  # Será preenchido em _draw_graph
        self.graph_timestamps = []  # Timestamps dos pontos
        self.graph_values = []  # Valores dos pontos
        
        # Vincular evento de movimento do mouse ao canvas para tooltip
        self.canvas.mpl_connect('motion_notify_event', self._on_graph_hover)
        
        # Label para informações
        self.graph_info = ttk.Label(graph_frame, text="Selecione um IP para ver o gráfico", justify="center")
        self.graph_info.pack(fill=tk.X, padx=5, pady=5)
        
        # Vincula clique na tabela para mostrar gráfico
        self.tree.bind("<ButtonRelease-1>", self._on_tree_select)
        self.tree.bind("<KeyRelease>", self._on_tree_select)
        # Vincula clique direito para abrir serviços
        self.tree.bind("<Button-3>", self._on_tree_right_click)
        # Vincula Ctrl+C para copiar texto da célula
        self.tree.bind("<Control-c>", self._on_copy_cell)
        # Vincula duplo-clique para editar nome (coluna 4)
        self.tree.bind("<Double-1>", self._on_edit_name)

        # Configura cores para as tags
        self.tree.tag_configure("updating", background="#FFFFCC")  # Amarelo claro para linha sendo atualizada
        self.tree.tag_configure("normal", background="white")
        self.tree.tag_configure("online", background="white")  # Sem cor de fundo
        self.tree.tag_configure("offline", background="#BDBDBD")  # Cinza médio
        
        # Inicia scan automaticamente
        self.root.after(500, self.start_scan)

    def _build_macs_tab(self):
        frame = ttk.Frame(self.tab_macs)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Frame superior com filtros
        filter_frame = ttk.LabelFrame(frame, text="Filtros")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="MAC:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.filter_mac = ttk.Entry(filter_frame, width=18)
        self.filter_mac.grid(row=0, column=1, sticky="w", padx=4, pady=4)
        
        ttk.Label(filter_frame, text="Nome:").grid(row=0, column=2, sticky="w", padx=4, pady=4)
        self.filter_nome = ttk.Entry(filter_frame, width=15)
        self.filter_nome.grid(row=0, column=3, sticky="w", padx=4, pady=4)
        
        ttk.Label(filter_frame, text="IP:").grid(row=0, column=4, sticky="w", padx=4, pady=4)
        self.filter_ip = ttk.Entry(filter_frame, width=12)
        self.filter_ip.grid(row=0, column=5, sticky="w", padx=4, pady=4)
        
        ttk.Label(filter_frame, text="Gateway:").grid(row=0, column=6, sticky="w", padx=4, pady=4)
        self.filter_gateway = ttk.Entry(filter_frame, width=12)
        self.filter_gateway.grid(row=0, column=7, sticky="w", padx=4, pady=4)
        
        ttk.Button(filter_frame, text="Aplicar", command=self._apply_macs_filter, width=10).grid(row=0, column=8, padx=4, pady=4)
        ttk.Button(filter_frame, text="Limpar", command=self._clear_macs_filter, width=10).grid(row=0, column=9, padx=4, pady=4)

        # Frame com ações (abaixo do filtro)
        actions_frame = ttk.LabelFrame(frame, text="Ações")
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        actions_inner = ttk.Frame(actions_frame)
        actions_inner.pack(fill=tk.X, padx=5, pady=5)
        
        self.macs_count_var = tk.StringVar(value="Total: 0 MACs")
        ttk.Label(actions_inner, textvariable=self.macs_count_var, font=("TkDefaultFont", 10, "bold")).pack(side=tk.LEFT, padx=(0,20))
        
        ttk.Button(actions_inner, text="Marcar filtrados", command=self._select_filtered_macs, width=18).pack(side=tk.LEFT, padx=(0,8))
        ttk.Button(actions_inner, text="Apagar selecionados", command=self._delete_selected_macs, width=20).pack(side=tk.LEFT, padx=0)
        columns = ("sel", "num", "mac", "nome", "last_ip", "gateway", "last_seen")
        self.tree_macs = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        self.tree_macs.heading("sel", text="☐", command=lambda: self._toggle_select_all_filtered_macs())
        self.tree_macs.heading("num", text="#", command=lambda: self._sort_macs_table("num"))
        self.tree_macs.heading("mac", text="MAC Address", command=lambda: self._sort_macs_table("mac"))
        self.tree_macs.heading("nome", text="Nome (Editar)", command=lambda: self._sort_macs_table("nome"))
        self.tree_macs.heading("last_ip", text="Último IP", command=lambda: self._sort_macs_table("last_ip"))
        self.tree_macs.heading("gateway", text="Gateway/AP", command=lambda: self._sort_macs_table("gateway"))
        self.tree_macs.heading("last_seen", text="Última Detecção", command=lambda: self._sort_macs_table("last_seen"))
        self.tree_macs.column("sel", width=40, anchor="center")
        self.tree_macs.column("num", width=40, anchor="center")
        self.tree_macs.column("mac", width=130, anchor="center")
        self.tree_macs.column("nome", width=150, anchor="w")
        self.tree_macs.column("last_ip", width=105, anchor="center")
        self.tree_macs.column("gateway", width=105, anchor="center")
        self.tree_macs.column("last_seen", width=130, anchor="center")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree_macs.yview)
        self.tree_macs.configure(yscrollcommand=vsb.set)

        self.tree_macs.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8), pady=5)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=5)

        # Bind para edição rápida e checkboxes
        self.tree_macs.bind("<Button-1>", self._on_mac_checkbox_click, add=True)
        self.tree_macs.bind("<Double-1>", self._on_mac_edit)

        # Área de edição/adição
        form = ttk.LabelFrame(frame, text="Adicionar/Editar")
        form.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)

        ttk.Label(form, text="MAC:").grid(row=0, column=0, sticky="w", pady=4, padx=4)
        self.entry_mac = ttk.Entry(form, width=22)
        self.entry_mac.grid(row=0, column=1, sticky="w", pady=4, padx=4)

        ttk.Label(form, text="Nome:").grid(row=1, column=0, sticky="w", pady=4, padx=4)
        self.entry_nome = ttk.Entry(form, width=30)
        self.entry_nome.grid(row=1, column=1, sticky="w", pady=4, padx=4)

        ttk.Button(form, text="Salvar / Atualizar", command=self._add_mac_nickname, width=22).grid(row=2, column=0, columnspan=2, pady=8, padx=4)
        ttk.Button(form, text="Remover", command=self._remove_mac_nickname, width=22).grid(row=3, column=0, columnspan=2, pady=4, padx=4)
        ttk.Button(form, text="Apagar Todos", command=self._clear_all_mac_nicknames, width=22).grid(row=4, column=0, columnspan=2, pady=4, padx=4)
        
        ttk.Separator(form, orient="horizontal").grid(row=5, column=0, columnspan=2, sticky="ew", pady=8, padx=4)
        
        ttk.Button(form, text="📄 Exportar TXT", command=self._export_macs_txt, width=22).grid(row=6, column=0, columnspan=2, pady=4, padx=4)
        ttk.Button(form, text="📊 Exportar CSV", command=self._export_macs_csv, width=22).grid(row=7, column=0, columnspan=2, pady=4, padx=4)
        ttk.Button(form, text="📥 Importar", command=self._import_macs_file, width=22).grid(row=8, column=0, columnspan=2, pady=4, padx=4)

        ttk.Label(form, text="Duplo-clique em uma linha para editar.", wraplength=200, justify="left").grid(row=9, column=0, columnspan=2, pady=8, padx=4)

        self.macs_selected = set()  # rastreia MACs marcados

    def _build_config_tab(self):
        frame = ttk.Frame(self.tab_config)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(frame, text="Tentativas de ping por host:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=1, to=20, textvariable=self.ping_attempts, width=5).grid(row=0, column=1, sticky="w")

        ttk.Label(frame, text="Intervalo entre scans (segundos):").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=10, to=900, textvariable=self.scan_interval, width=7).grid(row=1, column=1, sticky="w")

        ttk.Label(frame, text="Horas de histórico de ping (persistente):").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=1, to=168, textvariable=self.history_hours, width=7).grid(row=2, column=1, sticky="w")

        ttk.Label(frame, text="Dicas:").grid(row=3, column=0, sticky="nw", pady=(15,5))
        dicas = (
            "Use menos tentativas de ping para scans mais rápidos.",
            "Aumente o intervalo para evitar tráfego excessivo.",
            "Execute como administrador para melhor descoberta no Windows.",
        )
        ttk.Label(frame, text="\n".join(dicas), justify="left").grid(row=3, column=1, sticky="w")

    def _build_logs_tab(self):
        self.log_text = tk.Text(self.tab_logs, wrap="word", state=tk.DISABLED, height=25)
        vsb = ttk.Scrollbar(self.tab_logs, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0), pady=10)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=10, padx=(0,10))

    # ------------------------------------------------------------------
    # Persistência de sash position
    def _restore_sash_position(self):
        """Restaura a posição do divisor do gráfico"""
        try:
            if hasattr(self, 'paned_window') and hasattr(self, 'graph_sash_position'):
                # Para PanedWindow do tkinter, usa sash_place
                self.paned_window.sash_place(0, self.graph_sash_position, 1)
        except Exception as e:
            print(f"[WARN] Erro ao restaurar sash position: {e}")
    
    def _on_sash_moved(self, event=None):
        """Salva a posição do divisor ao ser movido"""
        try:
            if hasattr(self, 'paned_window'):
                # Para PanedWindow do tkinter, usa sash_coord
                pos = self.paned_window.sash_coord(0)
                if pos:
                    self.graph_sash_position = pos[0]  # Pega apenas coordenada X
                    self._save_config()
        except Exception:
            pass
    
    # ------------------------------------------------------------------
    # Tab MACs/Nomes
    def _normalize_mac(self, mac: str) -> str:
        """Normaliza MAC para formato AA:BB:CC:DD:EE:FF (maiúsculas)"""
        mac = mac.strip().upper().replace("-", ":")
        mac = mac.replace(" ", "")
        # Se vier sem dois pontos (12 chars), insere
        mac_plain = mac.replace(":", "")
        if len(mac_plain) == 12:
            mac = ":".join(mac_plain[i:i+2] for i in range(0, 12, 2))
        return mac.upper()  # Garante maiúsculas

    def _refresh_mac_table(self):
        if not hasattr(self, "tree_macs"):
            return
        for item in self.tree_macs.get_children():
            self.tree_macs.delete(item)
        
        # Obtém filtros se existirem
        filter_mac = self.filter_mac.get().strip().upper() if hasattr(self, 'filter_mac') else ""
        filter_nome = self.filter_nome.get().strip().lower() if hasattr(self, 'filter_nome') else ""
        filter_ip = self.filter_ip.get().strip() if hasattr(self, 'filter_ip') else ""
        filter_gateway = self.filter_gateway.get().strip() if hasattr(self, 'filter_gateway') else ""
        
        count = 0
        for mac, data in sorted(self.device_nicknames.items()):
            # Compatibilidade: se for string, converte para dict
            if isinstance(data, str):
                nome = data
                last_ip = "-"
                gateway = "-"
                last_seen = "-"
            else:
                nome = data.get("nome", "")
                last_ip = data.get("last_ip", "-")
                gateway = data.get("gateway", "-")
                last_seen = data.get("last_seen", "-")
            
            # Aplica filtros
            if filter_mac and filter_mac not in mac.upper():
                continue
            if filter_nome and filter_nome not in nome.lower():
                continue
            if filter_ip and filter_ip not in last_ip:
                continue
            if filter_gateway and filter_gateway not in gateway:
                continue
            
            count += 1
            sel_mark = "[x]" if mac in getattr(self, "macs_selected", set()) else "[ ]"
            self.tree_macs.insert("", tk.END, values=(sel_mark, count, mac, nome, last_ip, gateway, last_seen))

        # Atualiza contador
        if hasattr(self, "macs_count_var"):
            self.macs_count_var.set(f"Total: {count} MACs")
    
    def _update_macs_table_periodically(self):
        """Atualiza a tabela de MACs periodicamente"""
        self._refresh_mac_table()
        # Reagenda para 5 segundos
        self.root.after(5000, self._update_macs_table_periodically)
    
    def _apply_macs_filter(self):
        """Aplica os filtros na tabela de MACs"""
        self._refresh_mac_table()
        self.log("Filtros aplicados na tabela de MACs")
    
    def _clear_macs_filter(self):
        """Limpa os filtros da tabela de MACs"""
        if hasattr(self, 'filter_mac'):
            self.filter_mac.delete(0, tk.END)
        if hasattr(self, 'filter_nome'):
            self.filter_nome.delete(0, tk.END)
        if hasattr(self, 'filter_ip'):
            self.filter_ip.delete(0, tk.END)
        if hasattr(self, 'filter_gateway'):
            self.filter_gateway.delete(0, tk.END)
        self._refresh_mac_table()
        self.log("Filtros limpos")

    def _on_mac_checkbox_click(self, event):
        region = self.tree_macs.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree_macs.identify_column(event.x)
        if col != "#1":
            return
        item_id = self.tree_macs.identify_row(event.y)
        if not item_id:
            return
        values = self.tree_macs.item(item_id, 'values')
        if len(values) < 3:
            return
        mac = values[2]
        if mac in self.macs_selected:
            self.macs_selected.remove(mac)
            mark = "[ ]"
        else:
            self.macs_selected.add(mac)
            mark = "[x]"
        new_values = list(values)
        new_values[0] = mark
        self.tree_macs.item(item_id, values=new_values)

    def _toggle_select_all_filtered_macs(self):
        """Marca/desmarca todos os MACs filtrados com base no estado atual."""
        visible_macs = []
        for item_id in self.tree_macs.get_children():
            values = self.tree_macs.item(item_id, 'values')
            if len(values) >= 3:
                mac = values[2]
                visible_macs.append((item_id, mac, values))
        
        if not visible_macs:
            return
        
        # Verifica se todos já estão marcados
        all_marked = all(mac in self.macs_selected for _, mac, _ in visible_macs)
        
        # Se todos estão marcados, desmarca; caso contrário, marca
        if all_marked:
            for _, mac, values in visible_macs:
                self.macs_selected.discard(mac)
                new_values = list(values)
                new_values[0] = "[ ]"
                # Encontra o item_id novamente
                for item_id in self.tree_macs.get_children():
                    if self.tree_macs.item(item_id, 'values')[2] == mac:
                        self.tree_macs.item(item_id, values=new_values)
                        break
            self.log("MACs desmarcados")
        else:
            # Marca todos os visíveis
            for item_id, mac, values in visible_macs:
                self.macs_selected.add(mac)
                new_values = list(values)
                new_values[0] = "[x]"
                self.tree_macs.item(item_id, values=new_values)
            self.log(f"{len(visible_macs)} MAC(s) marcado(s)")

    def _select_filtered_macs(self):
        """Marca todos os MACs atualmente filtrados."""
        for item_id in self.tree_macs.get_children():
            values = self.tree_macs.item(item_id, 'values')
            if len(values) >= 3:
                mac = values[2]
                self.macs_selected.add(mac)
                new_values = list(values)
                new_values[0] = "[x]"
                self.tree_macs.item(item_id, values=new_values)
        self.log("MACs filtrados marcados")

    def _delete_selected_macs(self):
        """Apaga todos os MACs marcados."""
        if not self.macs_selected:
            messagebox.showinfo("Apagar", "Nenhum MAC marcado para apagar.")
            return
        if not messagebox.askyesno("Confirmar", "Apagar todos os MACs marcados?"):
            return
        removed = 0
        for mac in list(self.macs_selected):
            if mac in self.device_nicknames:
                del self.device_nicknames[mac]
                removed += 1
            self.macs_selected.discard(mac)
        self._save_nicknames()
        self._refresh_mac_table()
        self.log(f"{removed} MAC(s) apagados")
    
    def _sort_macs_table(self, col):
        """Ordena a tabela de MACs por coluna"""
        # Alterna direção se for a mesma coluna
        sort_column = getattr(self, 'sort_macs_column', None)
        sort_reverse = getattr(self, 'sort_macs_reverse', False)
        
        if sort_column == col:
            sort_reverse = not sort_reverse
        else:
            sort_column = col
            sort_reverse = False
        
        self.sort_macs_column = sort_column
        self.sort_macs_reverse = sort_reverse
        
        # Coleta dados da tabela
        items = []
        for item_id in self.tree_macs.get_children():
            values = self.tree_macs.item(item_id, 'values')
            if len(values) >= 7:
                items.append({
                    "id": item_id,
                    "sel": values[0],
                    "num": values[1],
                    "mac": values[2],
                    "nome": values[3],
                    "last_ip": values[4],
                    "gateway": values[5],
                    "last_seen": values[6]
                })
        
        # Define chave de ordenação
        def sort_key(item):
            val = item.get(col, "")
            if col == "sel":
                return 1 if str(val).strip().lower() in ("[x]", "x") else 0
            if col == "num":
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return 0
            
            # Para MAC, remove os : e converte
            if col == "mac":
                try:
                    return str(val).replace(":", "").upper()
                except AttributeError:
                    return ""
            # Para IP, converte para tupla numérica
            elif col == "last_ip" or col == "gateway":
                if val == "-":
                    return (999, 999, 999, 999) if not sort_reverse else (0, 0, 0, 0)
                try:
                    return tuple(int(x) for x in str(val).split('.'))
                except (ValueError, AttributeError):
                    return (0, 0, 0, 0)
            # Para timestamp, tenta converter para datetime
            elif col == "last_seen":
                if val == "-":
                    return "9999-99-99 99:99:99" if not sort_reverse else "0000-00-00 00:00:00"
                try:
                    # Converte DD/MM/YYYY HH:MM:SS para YYYY-MM-DD HH:MM:SS para ordenação
                    import datetime
                    dt = datetime.datetime.strptime(str(val), "%d/%m/%Y %H:%M:%S")
                    return dt.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, AttributeError):
                    return str(val)
            # Ordenação padrão (texto)
            return str(val).lower()
        
        # Ordena
        items.sort(key=sort_key, reverse=sort_reverse)
        
        # Reinsere na tabela mantendo os IDs
        for idx, item in enumerate(items):
            self.tree_macs.move(item["id"], "", idx)

    def _add_mac_nickname(self):
        mac_raw = self.entry_mac.get().strip()
        nome = self.entry_nome.get().strip()
        if not mac_raw or not nome:
            messagebox.showwarning("Dados incompletos", "Informe MAC e Nome.")
            return
        mac = self._normalize_mac(mac_raw)
        if len(mac.replace(":", "")) != 12:
            messagebox.showwarning("MAC inválido", "MAC deve ter 12 caracteres hexadecimais.")
            return
        # Preserva IP, gateway e timestamp se já existir
        if mac in self.device_nicknames:
            if isinstance(self.device_nicknames[mac], dict):
                self.device_nicknames[mac]["nome"] = nome
            else:
                self.device_nicknames[mac] = {"nome": nome, "last_ip": "-", "gateway": "-", "last_seen": "-"}
        else:
            self.device_nicknames[mac] = {"nome": nome, "last_ip": "-", "gateway": "-", "last_seen": "-"}
        self._save_nicknames()
        self._refresh_mac_table()
        self.log(f"Nome salvo para {mac}: {nome}")

    def _remove_mac_nickname(self):
        mac = None
        sel = self.tree_macs.selection()
        if sel:
            values = self.tree_macs.item(sel[0], 'values')
            if values:
                mac = values[2] if len(values) > 2 else None
        if not mac:
            mac_raw = self.entry_mac.get().strip()
            if mac_raw:
                mac = self._normalize_mac(mac_raw)
        if not mac or mac not in self.device_nicknames:
            messagebox.showinfo("Remover", "Selecione uma linha ou informe um MAC existente.")
            return
        del self.device_nicknames[mac]
        self.macs_selected.discard(mac)
        self._save_nicknames()
        self._refresh_mac_table()
        self.log(f"Nome removido para {mac}")

    def _clear_all_mac_nicknames(self):
        """Apaga todas as entradas da tabela de MACs."""
        if not self.device_nicknames:
            messagebox.showinfo("Apagar", "Não há MACs cadastrados.")
            return
        if not messagebox.askyesno("Confirmar", "Apagar todos os MACs cadastrados?"):
            return
        self.device_nicknames.clear()
        self.macs_selected.clear()
        self._save_nicknames()
        self._refresh_mac_table()
        self.log("Todas as entradas de MAC foram apagadas")

    def _on_mac_edit(self, event):
        item = self.tree_macs.identify("item", event.x, event.y)
        if not item:
            return
        values = self.tree_macs.item(item, 'values')
        if len(values) < 4:
            return
        mac = values[2]
        nome_atual = values[3]

        dialog = tk.Toplevel(self.root)
        dialog.title("Editar Nome")
        dialog.geometry("320x150")
        dialog.resizable(False, False)
        dialog.grab_set()

        ttk.Label(dialog, text=f"MAC: {mac}", font=("Arial", 9)).pack(pady=8)
        ttk.Label(dialog, text="Nome:").pack(pady=4)
        entry = ttk.Entry(dialog, width=32)
        entry.pack(pady=4, padx=10)
        entry.insert(0, nome_atual)
        entry.select_range(0, tk.END)
        entry.focus()

        def salvar():
            novo_nome = entry.get().strip()
            if not novo_nome:
                messagebox.showwarning("Nome vazio", "Informe um nome ou use Remover.")
                return
            # Preserva IP, gateway e timestamp se existir
            if mac in self.device_nicknames:
                if isinstance(self.device_nicknames[mac], dict):
                    self.device_nicknames[mac]["nome"] = novo_nome
                else:
                    self.device_nicknames[mac] = {"nome": novo_nome, "last_ip": "-", "gateway": "-", "last_seen": "-"}
            else:
                self.device_nicknames[mac] = {"nome": novo_nome, "last_ip": "-", "gateway": "-", "last_seen": "-"}
            self._save_nicknames()
            self._refresh_mac_table()
            self.log(f"Nome atualizado para {mac}: {novo_nome}")
            dialog.destroy()

        ttk.Button(dialog, text="Salvar", command=salvar, width=12).pack(pady=10)
        dialog.bind("<Return>", lambda e: salvar())
        dialog.bind("<Escape>", lambda e: dialog.destroy())
    
    def _export_macs_txt(self):
        """Exporta a tabela de MACs para arquivo TXT"""
        if not self.device_nicknames:
            messagebox.showinfo("Exportar", "Nenhum MAC cadastrado para exportar.")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivo de Texto", "*.txt"), ("Todos os arquivos", "*.*")],
            title="Salvar como TXT"
        )
        if not filepath:
            return
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("=" * 120 + "\n")
                f.write("TABELA DE MACS E NOMES - Analisador de Rede\n")
                f.write("=" * 120 + "\n\n")
                f.write(f"{'MAC Address':<20} {'Nome':<25} {'Último IP':<15} {'Gateway/AP':<15} {'Última Detecção'}\n")
                f.write("-" * 120 + "\n")
                for mac, data in sorted(self.device_nicknames.items()):
                    if isinstance(data, str):
                        nome, last_ip, gateway, last_seen = data, "-", "-", "-"
                    else:
                        nome = data.get("nome", "")
                        last_ip = data.get("last_ip", "-")
                        gateway = data.get("gateway", "-")
                        last_seen = data.get("last_seen", "-")
                    f.write(f"{mac:<20} {nome:<25} {last_ip:<15} {gateway:<15} {last_seen}\n")
                f.write("\n" + "=" * 120 + "\n")
                f.write(f"Total: {len(self.device_nicknames)} dispositivos\n")
            messagebox.showinfo("Sucesso", f"Exportado com sucesso para:\n{filepath}")
            self.log(f"MACs exportados para TXT: {filepath}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar TXT:\n{e}")
    
    def _export_macs_csv(self):
        """Exporta a tabela de MACs para arquivo CSV"""
        if not self.device_nicknames:
            messagebox.showinfo("Exportar", "Nenhum MAC cadastrado para exportar.")
            return
        
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Arquivo CSV", "*.csv"), ("Todos os arquivos", "*.*")],
            title="Salvar como CSV"
        )
        if not filepath:
            return
        
        try:
            with open(filepath, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(["MAC Address", "Nome", "Último IP", "Gateway/AP", "Última Detecção"])
                for mac, data in sorted(self.device_nicknames.items()):
                    if isinstance(data, str):
                        nome, last_ip, gateway, last_seen = data, "-", "-", "-"
                    else:
                        nome = data.get("nome", "")
                        last_ip = data.get("last_ip", "-")
                        gateway = data.get("gateway", "-")
                        last_seen = data.get("last_seen", "-")
                    writer.writerow([mac, nome, last_ip, gateway, last_seen])
            messagebox.showinfo("Sucesso", f"Exportado com sucesso para:\n{filepath}")
            self.log(f"MACs exportados para CSV: {filepath}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar CSV:\n{e}")

    def _import_macs_file(self):
        """Importa MACs de CSV ou TXT no formato exportado."""
        filepath = filedialog.askopenfilename(
            filetypes=[
                ("CSV/TXT", "*.csv *.txt"),
                ("CSV", "*.csv"),
                ("TXT", "*.txt"),
                ("Todos os arquivos", "*.*"),
            ],
            title="Importar MACs"
        )
        if not filepath:
            return
        importados = 0
        try:
            linhas = []
            with open(filepath, "r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    linhas.append(raw)
            def registrar(mac, nome, last_ip="-", gateway="-", last_seen="-"):
                mac_norm = self._normalize_mac(mac)
                if len(mac_norm.replace(":", "")) != 12:
                    return
                atual = self.device_nicknames.get(mac_norm, {}) if isinstance(self.device_nicknames.get(mac_norm), dict) else {}
                atual.setdefault("nome", nome)
                if nome:
                    atual["nome"] = nome
                atual["last_ip"] = last_ip or "-"
                atual["gateway"] = gateway or "-"
                atual["last_seen"] = last_seen or "-"
                self.device_nicknames[mac_norm] = atual
                importados_list.append(mac_norm)
            importados_list = []
            # Detecta CSV simples com ; ou ,
            for linha in linhas:
                partes = [p.strip() for p in re.split(r"[;,]", linha)]
                if len(partes) >= 2 and re.match(r"[0-9A-Fa-f]{2}[:\-]?", partes[0]):
                    mac, nome = partes[0], partes[1]
                    last_ip = partes[2] if len(partes) > 2 else "-"
                    gateway = partes[3] if len(partes) > 3 else "-"
                    last_seen = partes[4] if len(partes) > 4 else "-"
                    registrar(mac, nome, last_ip, gateway, last_seen)
                    importados += 1
            self._save_nicknames()
            self._refresh_mac_table()
            self.log(f"Importados {importados} MAC(s) de {filepath}")
            messagebox.showinfo("Importação", f"Importados {importados} MAC(s)")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao importar:\n{e}")

    # ------------------------------------------------------------------
    # Persistência de configurações
    def _load_config(self):
        """Carrega configurações do arquivo config.json"""
        default_config = {
            "ping_attempts": 4,
            "scan_interval": 60,
            "device_nicknames": {},
            "graph_sash_position": 650,
            "history_hours": 24,
        }
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    # Garante que device_nicknames existe
                    if "device_nicknames" not in config:
                        config["device_nicknames"] = {}
                    # Garante que ping_attempts e scan_interval existem
                    if "ping_attempts" not in config:
                        config["ping_attempts"] = default_config["ping_attempts"]
                    if "scan_interval" not in config:
                        config["scan_interval"] = default_config["scan_interval"]
                    if "graph_sash_position" not in config:
                        config["graph_sash_position"] = default_config["graph_sash_position"]
                    if "history_hours" not in config:
                        config["history_hours"] = default_config["history_hours"]
                    return config
        except Exception as e:
            print(f"Erro ao carregar config: {e}")
        
        # Salva config padrão se não existir arquivo
        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
        except:
            pass
        return default_config
    
    def _save_config(self):
        """Salva configurações no arquivo config.json"""
        try:
            config = {
                "ping_attempts": self.ping_attempts.get(),
                "scan_interval": self.scan_interval.get(),
                "history_hours": self.history_hours.get(),
                "device_nicknames": self.device_nicknames,
                "graph_sash_position": getattr(self, 'graph_sash_position', 650)
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Erro ao salvar config: {e}")
    
    def _on_closing(self):
        """Chamado ao fechar a janela"""
        self.stop_scan()
        self._save_nicknames()  # Salva rastreamento de MACs
        self._save_ping_history()
        self._save_config()
        self.root.destroy()
    
    def _on_tree_select(self, event=None):
        """Chamado quando um IP é selecionado na tabela"""
        selection = self.tree.selection()
        if selection:
            item_id = selection[0]
            values = self.tree.item(item_id, 'values')
            if len(values) > 2:
                ip_addr = values[2]  # IP agora está na coluna 3
                self.selected_ip = ip_addr  # Armazena IP selecionado
                self.btn_browser.config(state=tk.NORMAL)  # Habilita botão
                self._draw_graph(ip_addr)
    
    def _open_browser(self):
        """Abre o IP selecionado no browser"""
        if self.selected_ip:
            url = f"http://{self.selected_ip}"
            try:
                webbrowser.open(url)
                self.log(f"Abrindo {url} no browser...")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível abrir o browser: {e}")
    
    def _on_graph_hover(self, event):
        """Mostra tooltip ao passar o mouse sobre um ponto no gráfico"""
        if event.inaxes != self.ax or not self.graph_values or not self.graph_timestamps:
            # Remove tooltip se sair da área do gráfico
            self.graph_info.config(text="Mova o mouse sobre um ponto para ver detalhes")
            return
        
        # Obtém coordenadas do mouse em relação ao gráfico
        x_data = event.xdata
        if x_data is None:
            return
        
        # Encontra o ponto mais próximo
        x_index = int(round(x_data)) - 1  # Converte para índice (começa em 0)
        
        # Verifica se o índice é válido
        if 0 <= x_index < len(self.graph_values):
            valor = self.graph_values[x_index]
            timestamp = self.graph_timestamps[x_index] if x_index < len(self.graph_timestamps) else "N/A"
            
            # Formata a exibição
            tooltip_text = f"Hora: {timestamp} | Ping: {valor:.2f}ms"
            self.graph_info.config(text=tooltip_text)
    
    def _on_tree_right_click(self, event):
        """Clique direito na tabela para abrir serviços descobertos"""
        item = self.tree.identify("item", event.x, event.y)
        column = self.tree.identify_column(event.x)
        if not item:
            return

        # Coluna de Serviços agora é a #9 (índice 8)
        if column != "#9":
            return

        values = self.tree.item(item, 'values')
        if len(values) < 9:
            return

        ip_addr = values[2]  # IP agora está na coluna 3
        servicos_str = values[8]  # Serviços está na coluna 9

        # Mostra menu popup com portas descobertas
        self._show_ports_menu(event.x_root, event.y_root, ip_addr, servicos_str)
    
    def _show_ports_menu(self, x, y, ip_addr, servicos_str):
        """Cria menu popup com portas clicáveis"""
        if servicos_str == "Nenhum":
            messagebox.showinfo("Serviços", f"Nenhum serviço descoberto em {ip_addr}")
            return
        
        # Cria menu popup
        menu = tk.Menu(self.root, tearoff=False)
        # Adiciona título (desabilitado para parecer apenas informativo)
        menu.add_command(label=f"Portas de {ip_addr}", state=tk.DISABLED)
        menu.add_separator()
        
        # Extrai portas do formato "SSH(22), HTTP(80), MySQL(3306)"
        ports_info = []
        for parte in servicos_str.split(", "):
            # Extrai nome do serviço e número da porta
            match = re.match(r"([A-Za-z0-9\-]+)\((\d+)\)", parte.strip())
            if match:
                nome_servico = match.group(1)
                porta = int(match.group(2))
                ports_info.append((nome_servico, porta))
        
        # Adiciona as portas ao menu como items clicáveis
        for nome_servico, porta in ports_info:
            menu.add_command(
                label=f"{nome_servico} ({porta})",
                command=lambda s=nome_servico, p=porta, ip=ip_addr: self._open_port(ip, p, s)
            )
        
        # Mostra o menu na posição do clique
        try:
            menu.tk_popup(x, y)
        except Exception as e:
            self.log(f"Erro ao abrir menu: {e}")
    
    def _open_port(self, ip_addr, porta, servico):
        """Abre uma porta com o protocolo apropriado"""
        # Mapeamento de portas comuns para protocolos
        protocolos = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            53: "dns",
            80: "http",
            443: "https",
            110: "pop3",
            143: "imap",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8000: "http",
            8080: "http",
            8443: "https",
            8888: "http",
            27017: "mongodb",
        }
        
        protocolo = protocolos.get(porta, "http")  # Default para HTTP
        
        # Constrói a URL
        if protocolo in ["http", "https"]:
            url = f"{protocolo}://{ip_addr}:{porta}"
        elif protocolo == "ssh":
            url = f"ssh://{ip_addr}"
        elif protocolo == "ftp":
            url = f"ftp://{ip_addr}"
        else:
            url = f"http://{ip_addr}:{porta}"  # Fallback
        
        try:
            webbrowser.open(url)
            self.log(f"Abrindo {servico}({porta}) em {ip_addr}: {url}")
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir {servico}({porta}): {e}")
    
    def _on_copy_cell(self, event):
        """Copia o texto da célula selecionada para a área de transferência"""
        try:
            selection = self.tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            values = self.tree.item(item_id, 'values')
            
            # Identifica qual coluna está selecionada
            focus = self.tree.focus()
            if focus == item_id:
                # Copia todas as colunas ou apenas a focada
                texto = " | ".join(str(v) for v in values)
                self.root.clipboard_clear()
                self.root.clipboard_append(texto)
                self.log(f"Copiado para clipboard: {texto[:50]}...")
        except Exception as e:
            self.log(f"Erro ao copiar: {e}")
    
    def _on_edit_name(self, event):
        """Duplo-clique: edita nome (coluna 4) ou copia valor de outras colunas"""
        item = self.tree.identify("item", event.x, event.y)
        column = self.tree.identify_column(event.x)
        
        if not item:
            return
        
        values = self.tree.item(item, 'values')
        
        # Se NÃO for coluna "nome" (#5), copia o valor da célula
        if column != "#5":
            try:
                # Mapeia número da coluna para índice
                column_index = int(column.replace("#", "")) - 1
                if 0 <= column_index < len(values):
                    valor = str(values[column_index])
                    self.root.clipboard_clear()
                    self.root.clipboard_append(valor)
                    
                    # Atualiza status e log
                    self.status_var.set(f"✓ Copiado: {valor[:50]}")
                    self.log(f"Copiado: {valor}")
                    
                    # Remove status após 2 segundos
                    self.root.after(2000, lambda: self.status_var.set("Pronto"))
            except Exception as e:
                self.log(f"Erro ao copiar: {e}")
            return
        
        # Se for coluna "nome" (#5), edita o nome
        if len(values) < 5:
            return
        
        mac = values[3]  # MAC está na coluna 4 (índice 3)
        nome_atual = values[4]  # Nome está na coluna 5 (índice 4)
        
        # Cria janela de edição
        dialog = tk.Toplevel(self.root)
        dialog.title("Editar Nome do Dispositivo")
        dialog.geometry("400x180")
        dialog.resizable(False, False)
        dialog.grab_set()  # Modal
        
        # Informações do dispositivo
        ttk.Label(dialog, text=f"Dispositivo: {values[2]}", font=("Arial", 9)).pack(pady=5)
        ttk.Label(dialog, text=f"MAC: {mac}", font=("Arial", 9)).pack(pady=0)
        ttk.Label(dialog, text="Novo nome:").pack(pady=8)
        
        # Campo de entrada
        entry = ttk.Entry(dialog, width=40)
        entry.pack(pady=5, padx=10)
        entry.insert(0, nome_atual)
        entry.select_range(0, tk.END)
        entry.focus()
        
        def salvar_nome():
            novo_nome = entry.get().strip()
            if novo_nome:
                # Atualiza dicionário preservando metadados
                atual = self.device_nicknames.get(mac, {})
                if isinstance(atual, dict):
                    atual["nome"] = novo_nome
                else:
                    atual = {
                        "nome": novo_nome,
                        "last_ip": "-",
                        "gateway": self.current_gateway,
                        "last_seen": "-",
                    }
                self.device_nicknames[mac] = atual
                self._save_nicknames()
                
                # Atualiza tabela
                new_values = list(values)
                new_values[3] = novo_nome
                self.tree.item(item, values=new_values)
                
                self.log(f"Nome atualizado para {mac}: {novo_nome}")
            else:
                # Remove nome se vazio
                if mac in self.device_nicknames:
                    del self.device_nicknames[mac]
                    self._save_nicknames()
                    new_values = list(values)
                    new_values[3] = ""
                    self.tree.item(item, values=new_values)
                    self.log(f"Nome removido para {mac}")
            
            dialog.destroy()
        
        def cancelar():
            dialog.destroy()
        
        # Botões
        frame_buttons = ttk.Frame(dialog)
        frame_buttons.pack(pady=10)
        
        ttk.Button(frame_buttons, text="Salvar", command=salvar_nome, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_buttons, text="Cancelar", command=cancelar, width=12).pack(side=tk.LEFT, padx=5)
        
        # Fecha ao apertar Enter
        dialog.bind("<Return>", lambda e: salvar_nome())
        dialog.bind("<Escape>", lambda e: cancelar())
    
    def _load_nicknames(self):
        """Carrega apelidos de dispositivos do arquivo de configuração"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    loaded = config.get("device_nicknames", {})
                    normalized = {}
                    for mac_key, data in loaded.items():
                        mac_norm = self._normalize_mac(mac_key)
                        if isinstance(data, str):
                            normalized[mac_norm] = {
                                "nome": data,
                                "last_ip": "-",
                                "gateway": "-",
                                "last_seen": "-",
                            }
                        else:
                            normalized[mac_norm] = {
                                "nome": data.get("nome", ""),
                                "last_ip": data.get("last_ip", "-"),
                                "gateway": data.get("gateway", "-"),
                                "last_seen": data.get("last_seen", "-"),
                            }
                    self.device_nicknames = normalized
        except Exception as e:
            print(f"Erro ao carregar apelidos: {e}")
    
    def _save_nicknames(self):
        """Salva apelidos de dispositivos no arquivo de configuração"""
        try:
            config = {
                "ping_attempts": self.ping_attempts.get(),
                "scan_interval": self.scan_interval.get(),
                "history_hours": self.history_hours.get(),
            }
            
            # Carrega config existente para não perder outras configurações
            if os.path.exists(self.config_file):
                try:
                    with open(self.config_file, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                        # Preserva outras configurações que possam existir
                        for key in existing:
                            if key not in config:
                                config[key] = existing[key]
                except:
                    pass
            
            config["device_nicknames"] = self.device_nicknames
            
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                
            print(f"[DEBUG] Config salvo: {len(self.device_nicknames)} nomes salvos")
        except Exception as e:
            print(f"Erro ao salvar apelidos: {e}")

    def _load_ping_history(self):
        """Carrega histórico de pings persistente."""
        try:
            if os.path.exists(self.ping_history_file):
                with open(self.ping_history_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                with self.ping_history_lock:
                    for ip, registros in data.items():
                        lista = []
                        for entry in registros:
                            if isinstance(entry, dict):
                                ms = entry.get("ms")
                                ts = entry.get("ts")
                            elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                                ms, ts = entry[0], entry[1]
                            else:
                                continue
                            lista.append((ms, ts))
                        self.ping_history[ip] = lista
                self._prune_history_by_hours()
        except Exception as e:
            print(f"Erro ao carregar histórico de ping: {e}")

    def _save_ping_history(self):
        """Salva histórico de pings respeitando a janela configurada."""
        try:
            self._prune_history_by_hours()
            with self.ping_history_lock:
                serializado = {}
                for ip, lista in self.ping_history.items():
                    serializado[ip] = []
                    for item in lista:
                        if isinstance(item, tuple) and len(item) >= 2:
                            serializado[ip].append({"ms": item[0], "ts": item[1]})
                with open(self.ping_history_file, "w", encoding="utf-8") as f:
                    json.dump(serializado, f, indent=2, ensure_ascii=False)
            self.last_ping_save = time.time()
        except Exception as e:
            print(f"Erro ao salvar histórico de ping: {e}")

    def _save_ping_history_throttled(self, interval_seconds: int = 30):
        if time.time() - self.last_ping_save >= interval_seconds:
            self._save_ping_history()

    def _prune_history_by_hours(self):
        """Remove amostras fora da janela configurada."""
        try:
            horas = max(1, int(self.history_hours.get()))
            limite = datetime.now() - timedelta(hours=horas)
        except Exception:
            return
        with self.ping_history_lock:
            for ip, lista in list(self.ping_history.items()):
                nova = []
                for item in lista:
                    if not isinstance(item, tuple) or len(item) < 2:
                        continue
                    ts = item[1]
                    try:
                        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        continue
                    if dt >= limite:
                        nova.append(item)
                self.ping_history[ip] = nova

    def _get_recent_pings(self, ip_addr: str):
        self._prune_history_by_hours()
        with self.ping_history_lock:
            return list(self.ping_history.get(ip_addr, []))

    def _on_history_hours_change(self):
        self._prune_history_by_hours()
        self._save_ping_history()
        self._save_config()
    
    def _draw_graph(self, ip_addr):
        """Desenha gráfico com todos os pings do histórico e curva de tendência"""
        pings = self._get_recent_pings(ip_addr)
        if not pings:
            self.ax.clear()
            self.ax.text(0.5, 0.5, f"Nenhum dado para {ip_addr}", 
                        ha='center', va='center', transform=self.ax.transAxes)
            self.canvas.draw()
            self.graph_info.config(text=f"Nenhum dado para {ip_addr}")
            return
        
        # Limpa o gráfico anterior
        self.ax.clear()
        
        # Extrai valores e timestamps (compatível com tuplas ou valores simples)
        valores_ping = []
        timestamps = []
        for p in pings:
            if isinstance(p, tuple) and len(p) >= 2:
                valores_ping.append(p[0])
                timestamps.append(p[1])
            else:
                valores_ping.append(p)
                timestamps.append("")
        
        # Estatísticas
        max_ping = max(valores_ping)
        min_ping = min(valores_ping)
        avg_ping = sum(valores_ping) / len(valores_ping)
        
        # Cria índices para o eixo X
        x_vals = np.array(range(1, len(valores_ping) + 1))
        y_vals = np.array(valores_ping)
        
        # Desenha a linha principal de pings
        self.ax.plot(x_vals, y_vals, color='#2196F3', linewidth=2, marker='o', 
                    markersize=5, label='Ping (ms)', markerfacecolor='#2196F3', 
                    markeredgecolor='#1976D2', markeredgewidth=1, alpha=0.8)
        
        # Curva de tendência (polyfit grau 2)
        if len(valores_ping) >= 3:
            try:
                z = np.polyfit(x_vals, y_vals, 2)
                p = np.poly1d(z)
                x_smooth = np.linspace(x_vals.min(), x_vals.max(), 100)
                y_smooth = p(x_smooth)
                self.ax.plot(x_smooth, y_smooth, color='#4CAF50', linewidth=2.5, 
                            label='Tendência', linestyle='--', alpha=0.8)
            except:
                pass
        
        # Destaca o último ponto
        if valores_ping:
            self.ax.plot(len(valores_ping), valores_ping[-1], color='#FF5722', marker='o', 
                        markersize=8, markeredgecolor='#E64A19', markeredgewidth=2, 
                        label='Último valor', zorder=5)
        
        # Linha de média
        self.ax.axhline(y=avg_ping, color='#FFC107', linestyle=':', linewidth=2, 
                       label=f'Média: {int(avg_ping)}ms', alpha=0.7)
        
        # Configuração dos eixos com timestamps
        # Mostra apenas alguns timestamps para não poluir o gráfico
        step = max(1, len(timestamps) // 10)  # até 10 timestamps
        x_ticks = list(range(0, len(timestamps), step)) + [len(timestamps) - 1]
        x_ticks = sorted(set(x_ticks))
        x_labels = [timestamps[i-1] if i > 0 and i <= len(timestamps) else "" for i in x_ticks]
        
        self.ax.set_xticks(x_ticks)
        self.ax.set_xticklabels(x_labels, rotation=45, ha='right', fontsize=8)
        self.ax.set_ylabel('Latência (ms)', fontsize=9, color='#333')
        self.ax.set_title(f'Histórico Completo de Ping - {ip_addr}', fontsize=11, fontweight='bold')
        self.ax.grid(True, alpha=0.3, linestyle=':')
        self.ax.set_facecolor('#fafafa')
        self.ax.legend(loc='upper right', fontsize=8, framealpha=0.9)
        
        # Ajusta espaçamento
        self.fig.tight_layout()
        
        # Armazena dados para tooltip
        self.graph_values = valores_ping
        self.graph_timestamps = timestamps
        
        # Redesenha o canvas
        self.canvas.draw()
        
        # Atualiza informações
        self.graph_info.config(
            text=f"{ip_addr} | Min: {int(min_ping)}ms | Avg: {int(avg_ping)}ms | Max: {int(max_ping)}ms | Total: {len(valores_ping)} amostras"
        )

    # ------------------------------------------------------------------
    # Logging e status
    def log(self, msg: str):
        timestamp = time.strftime("%H:%M:%S")
        self.queue.put(("log", f"[{timestamp}] {msg}\n"))

    def set_status(self, msg: str):
        self.queue.put(("status", msg))

    # ------------------------------------------------------------------
    # Histórico de pings
    def _extrair_ms_do_ping(self, ping_str):
        """Extrai valor numérico em ms do string de ping"""
        try:
            # Formato: "X.XX ms (Y/Z)"
            m = re.search(r"(\d+\.?\d*)\s*ms", ping_str)
            if m:
                return float(m.group(1))
        except:
            pass
        return None

    def _gerar_grafico_ping(self, ip):
        """Retorna uma string vazia - gráfico agora é visual no Canvas"""
        pings_raw = self._get_recent_pings(ip)
        if not pings_raw:
            return "▪"
        
        pings = [p[0] if isinstance(p, tuple) else p for p in pings_raw]
        avg = sum(pings) / len(pings) if pings else 0
        
        if avg < 20:
            return "●●●●● (Excelente)"  # verde
        elif avg < 50:
            return "●●●●○ (Bom)"  # amarelo
        elif avg < 100:
            return "●●●○○ (Ok)"  # laranja
        else:
            return "●●○○○ (Lento)"  # vermelho

    def _gerar_micrografico(self, ip):
        """Gera um micrográfico em pixels (sparkline) do histórico de ping com a leitura atual"""
        dados = self._get_recent_pings(ip)[-10:]
        if not dados:
            return "sem dados"
        
        # Extrai valores de ping (compatível com tuplas (valor, timestamp))
        pings = [d[0] if isinstance(d, tuple) else d for d in dados]
        
        # Normaliza os valores para escala de 0-8 (altura dos caracteres)
        max_ping = max(pings)
        min_ping = min(pings)
        span = max_ping - min_ping if max_ping > min_ping else 1
        
        # Caracteres em escala de altura (pixels)
        chars = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        
        result = ""
        for ping in pings:
            normalized = (ping - min_ping) / span
            idx = int(normalized * (len(chars) - 1))
            idx = max(0, min(idx, len(chars) - 1))
            result += chars[idx]
        
        # Adiciona a leitura atual no final
        current_ping = pings[-1]
        result += f" {int(current_ping)}ms"
        
        return result

    def _discover_gateway_identifier(self, ip_local: str, mascara: str) -> str:
        """Tenta obter um identificador estável do gateway/AP sem depender do IP."""
        try:
            gateway_ip = None
            texto_ipconfig = run_cmd_capture(["ipconfig"]) or ""
            # Captura primeiro gateway padrão IPv4
            m_gw = re.search(r"Gateway\s+padr[ãa]o.*?:\s*(\d+\.\d+\.\d+\.\d+)", texto_ipconfig, re.IGNORECASE)
            if m_gw:
                gateway_ip = m_gw.group(1)

            gateway_mac = None
            if gateway_ip:
                texto_arp = run_cmd_capture(["arp", "-a"]) or ""
                m_arp = re.search(rf"{re.escape(gateway_ip)}\s+([A-Fa-f0-9\-:]+)", texto_arp)
                if m_arp:
                    gateway_mac = self._normalize_mac(m_arp.group(1))

            ssid = None
            bssid = None
            texto_wlan = run_cmd_capture(["netsh", "wlan", "show", "interfaces"]) or ""
            if texto_wlan:
                m_ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", texto_wlan, re.IGNORECASE | re.MULTILINE)
                m_bssid = re.search(r"^\s*BSSID\s*:\s*([A-Fa-f0-9:]+)", texto_wlan, re.IGNORECASE | re.MULTILINE)
                if m_ssid:
                    ssid = m_ssid.group(1).strip()
                if m_bssid:
                    bssid = self._normalize_mac(m_bssid.group(1))

            partes = []
            if gateway_mac:
                partes.append(f"GW:{gateway_mac}")
            if bssid:
                partes.append(f"BSSID:{bssid}")
            if ssid:
                partes.append(f"SSID:{ssid}")

            if partes:
                return " | ".join(partes)

            return "desconhecido"
        except Exception as exc:
            self.log(f"Falha ao identificar gateway: {exc}")
            return "desconhecido"

    # ------------------------------------------------------------------
    # Scans
    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.stop_event.clear()
        # Inicia apenas um scan (ARP + threads)
        self.scan_thread = threading.Thread(target=self._do_scan, daemon=True)
        self.scan_thread.start()
        self.btn_start.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.set_status("Iniciando monitoramento...")
        self.log("Monitoramento iniciado - dispositivos serão atualizados continuamente")

    def stop_scan(self):
        self.stop_event.set()
        # Aguarda threads terminarem
        with self.device_lock:
            self.device_threads.clear()
        self.btn_start.configure(state=tk.NORMAL)
        self.btn_stop.configure(state=tk.DISABLED)
        self.set_status("Parado")
        self.log("Monitoramento parado")

    def _do_scan(self):
        """Realiza varredura ARP e lança threads por dispositivo"""
        try:
            self.log("Obtendo interface ativa...")
            ip, mask = obter_interface_ativa()
            if not ip:
                self.log("Nenhuma interface ativa encontrada")
                return
            self.log(f"Interface: {ip} / {mask}")

            # Calcula identificador único da rede/gateway
            self.current_gateway = self._discover_gateway_identifier(ip, mask)
            self.log(f"Gateway identificado: {self.current_gateway}")

            self.log("Executando ARP scan...")
            dispositivos = fazer_arp_scan(ip, mask)
            if not dispositivos:
                self.log("Nenhum dispositivo encontrado no ARP")
                return

            total = len(dispositivos)
            self.set_status(f"Descobertos {total} dispositivos, iniciando monitoramento...")
            self.log(f"ARP scan encontrou {total} dispositivos")
            
            # Lança uma thread por dispositivo (monitoramento paralelo)
            idx = 0
            for ip_addr, mac in sorted(dispositivos.items(), key=lambda x: [int(p) for p in x[0].split('.')]):
                idx += 1
                
                # Verifica se já existe thread deste IP
                with self.device_lock:
                    if ip_addr not in self.device_threads:
                        # Cria nova thread para monitorar este dispositivo
                        thread = threading.Thread(
                            target=self._monitor_device,
                            args=(idx, ip_addr, mac),
                            daemon=True,
                            name=f"Device-{ip_addr}"
                        )
                        self.device_threads[ip_addr] = thread
                        thread.start()
            
            self.set_status(f"Monitorando {total} dispositivos")
            # Salva rastreamento após scan inicial
            self._save_nicknames()
        except Exception as exc:
            self.log(f"Erro no scan: {exc}")

    def _monitor_device(self, num, ip_addr, mac):
        """Thread contínua para monitorar um único dispositivo"""
        tentativas = max(1, self.ping_attempts.get())
        
        # Inicializa histórico se necessário
        with self.ping_history_lock:
            if ip_addr not in self.ping_history:
                self.ping_history[ip_addr] = []
        
        # Primeiro, coleta informações gerais (uma vez)
        hostname, fabricante = obter_info_dispositivo(ip_addr, mac)
        netbios = obter_netbios(ip_addr)
        
        # Escaneia portas para descobrir serviços
        self.log(f"[{ip_addr}] Escaneando portas...")
        servicos = escanear_portas(ip_addr, timeout=1)
        self.log(f"[{ip_addr}] Serviços encontrados: {servicos}")
        
        # Loop contínuo de ping enquanto o dispositivo está ativo
        while not self.stop_event.is_set():
            try:
                # Realiza ping
                ping = calcular_ping(ip_addr, tentativas=tentativas)
                
                # Extrai valor numérico e armazena no histórico com timestamp
                ms_valor = self._extrair_ms_do_ping(ping)
                online_arp_tcp, metodo = verificar_online_arp_tcp(ip_addr)
                status_bool = (ms_valor is not None) or online_arp_tcp
                status_icon = "ONLINE" if status_bool else "OFFLINE"
                if ms_valor is not None:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with self.ping_history_lock:
                        self.ping_history.setdefault(ip_addr, []).append((ms_valor, timestamp))
                    self._prune_history_by_hours()
                    self._save_ping_history_throttled()
                
                # Gera gráfico com histórico
                historico = self._gerar_grafico_ping(ip_addr)
                grafico = self._gerar_micrografico(ip_addr)
                
                # Prepara item para a tabela
                item = {
                    "num": num,
                    "ip": ip_addr,
                    "hostname": hostname,
                    "netbios": netbios,
                    "fabricante": fabricante,
                    "servicos": servicos,
                    "ping": ping,
                    "grafico": grafico,
                    "historico": historico,
                    "mac": mac,
                    "status": status_icon,
                }
                
                # Log no terminal
                self.log(f"[{ip_addr}] {ping} | MAC: {mac} | {fabricante}")
                
                # Atualiza tabela em tempo real
                self.queue.put(("table_item", item))
                
                # Aguarda antes do próximo ping (5 segundos entre pings)
                for _ in range(5):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.log(f"Erro monitorando {ip_addr}: {e}")
                time.sleep(5)

    # ------------------------------------------------------------------
    # Queue processing
    def _process_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "status":
                    self.status_var.set(payload)
                elif kind == "clear_table":
                    self._clear_table()
                elif kind == "table_item":
                    self._add_table_item(payload)
                    # Atualiza gráfico em tempo real se o IP está selecionado
                    if self.selected_ip and payload["ip"] == self.selected_ip:
                        self._draw_graph(self.selected_ip)
                elif kind == "table":
                    self._update_table(payload)
                self.queue.task_done()
        except Empty:
            pass
        self.root.after(200, self._process_queue)

    def _append_log(self, text: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _clear_table(self):
        """Limpa todos os itens da tabela"""
        self.tree.delete(*self.tree.get_children())
        self.table_ips.clear()  # Limpa também o rastreamento de IPs

    def _remove_tag_updating(self, item_id):
        """Remove a tag de destaque de uma linha e mantém a tag apropriada baseada no status"""
        try:
            values = self.tree.item(item_id, 'values')
            if len(values) > 1:
                status = values[1]
                # Mantém a tag "online" se o status for ONLINE, caso contrário "offline"
                tag = ("online",) if status == "ONLINE" else ("offline",)
                self.tree.item(item_id, tags=tag)
            else:
                self.tree.item(item_id, tags=("offline",))
        except:
            pass

    def _auto_resize_columns(self):
        """Ajusta a largura das colunas ao maior conteúdo visível."""
        if not hasattr(self, "tree"):
            return
        try:
            font = tkfont.nametofont(self.tree.cget("font"))
            padding = 16  # pequeno espaço extra
            for col in self.tree["columns"]:
                header_text = self.tree.heading(col).get("text", "")
                max_width = font.measure(str(header_text))
                for item_id in self.tree.get_children():
                    val = self.tree.set(item_id, col)
                    max_width = max(max_width, font.measure(str(val)))
                self.tree.column(col, width=max_width + padding)
        except Exception:
            pass

    def _add_table_item(self, item):
        """Adiciona ou atualiza um item na tabela, evitando duplicatas"""
        ip_addr = item["ip"].strip()
        mac_addr = self._normalize_mac(item["mac"])  # Garante formato normalizado
        
        # Atualiza rastreamento de IP e timestamp para este MAC
        import datetime
        timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        if mac_addr in self.device_nicknames:
            if isinstance(self.device_nicknames[mac_addr], str):
                # Migra formato antigo para novo
                nome_antigo = self.device_nicknames[mac_addr]
                self.device_nicknames[mac_addr] = {
                    "nome": nome_antigo,
                    "last_ip": ip_addr,
                    "gateway": self.current_gateway,
                    "last_seen": timestamp,
                }
            else:
                # Atualiza IP, gateway e timestamp
                self.device_nicknames[mac_addr]["last_ip"] = ip_addr
                self.device_nicknames[mac_addr]["gateway"] = self.current_gateway
                self.device_nicknames[mac_addr]["last_seen"] = timestamp
        else:
            # Cria nova entrada sem nome
            self.device_nicknames[mac_addr] = {
                "nome": "",
                "last_ip": ip_addr,
                "gateway": self.current_gateway,
                "last_seen": timestamp,
            }
        
        # Salva periodicamente (a cada 10 dispositivos para não sobrecarregar)
        if len(self.device_nicknames) % 10 == 0:
            self._save_nicknames()
        
        # Obtém o nome (apelido) se existir
        nome = self.device_nicknames[mac_addr].get("nome", "") if isinstance(self.device_nicknames[mac_addr], dict) else ""
        
        # Verifica se o IP já existe usando o dicionário de rastreamento
        if ip_addr in self.table_ips:
            # Atualiza a linha existente
            existing_item_id = self.table_ips[ip_addr]
            old_values = self.tree.item(existing_item_id, 'values')
            
            self.tree.item(existing_item_id, values=(
                old_values[0],  # mantém o número original
                item.get("status", ""),
                item["ip"],
                mac_addr.upper(),  # MAC em maiúsculas
                nome,  # Nome/apelido
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item["servicos"],
                item["ping"],
                item["grafico"],
                item["historico"]
            ), tags=("updating", "online" if item.get("status") == "ONLINE" else "offline"))
            
            # Agenda remover a tag de destaque após 500ms
            self.root.after(500, lambda: self._remove_tag_updating(existing_item_id))
        else:
            # Insere nova linha
            item_id = self.tree.insert("", tk.END, values=(
                item["num"],
                item.get("status", ""),
                item["ip"],
                mac_addr.upper(),  # MAC em maiúsculas
                nome,  # Nome/apelido
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item["servicos"],
                item["ping"],
                item["grafico"],
                item["historico"]
            ), tags=("updating", "online" if item.get("status") == "ONLINE" else "offline"))
            
            # Registra o IP no dicionário de rastreamento
            self.table_ips[ip_addr] = item_id
            
            # Agenda remover a tag de destaque após 500ms
            self.root.after(500, lambda: self._remove_tag_updating(item_id))

        # Ajusta larguras após inserir/atualizar
        self._auto_resize_columns()

    def _sort_table(self, col):
        """Ordena a tabela por coluna"""
        # Alterna direção se for a mesma coluna
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = False

        # Coleta dados da tabela
        items = []
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, 'values')
            if len(values) >= 12:  # Garante que tem todas as colunas
                items.append({
                    "id": item_id,
                    "num": values[0],
                    "status": values[1],
                    "ip": values[2],
                    "mac": values[3],
                    "nome": values[4],
                    "hostname": values[5],
                    "netbios": values[6],
                    "fabricante": values[7],
                    "servicos": values[8],
                    "ping": values[9],
                    "grafico": values[10],
                    "historico": values[11]
                })

        # Define chave de ordenação
        def sort_key(item):
            val = item.get(col, "")
            # Tenta converter para número se for ping ou num
            if col == "num":
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return 0
            elif col == "ping":
                try:
                    # Extrai valor numérico do ping (ex: "5.23 ms (5/5)")
                    return float(val.split()[0]) if val and val != "Sem resposta" else float('inf')
                except (ValueError, IndexError, AttributeError):
                    return float('inf')
            elif col == "status":
                return str(val)
            # Para IP, converte para tupla numérica
            elif col == "ip":
                try:
                    return tuple(int(x) for x in str(val).split('.'))
                except (ValueError, AttributeError):
                    return (0, 0, 0, 0)
            # Para MAC, remove os : e converte
            elif col == "mac":
                try:
                    return str(val).replace(":", "").upper()
                except AttributeError:
                    return ""
            # Ordenação padrão (texto)
            return str(val).lower()

        # Ordena
        items.sort(key=sort_key, reverse=self.sort_reverse)

        # Reinsere na tabela mantendo os IDs
        for idx, item in enumerate(items):
            self.tree.move(item["id"], "", idx)

    def _filter_online_only(self):
        """Filtra a tabela para mostrar apenas dispositivos online (status = ONLINE)"""
        show_online_only = self.show_online_only_var.get()
        
        # Coleta todos os itens (incluindo os que já estão na treeview)
        all_item_ids = self.tree.get_children()
        
        if show_online_only:
            # Oculta itens offline
            for item_id in all_item_ids:
                values = self.tree.item(item_id, 'values')
                if len(values) > 1:
                    status = values[1]  # coluna "status" é a coluna 1
                    if status != "ONLINE":
                        self.tree.detach(item_id)
        else:
            # Mostra todos os itens (incluindo os detached)
            # Primeiro, reinsere os itens que estão ocultos
            # Para fazer isso, precisamos manter um registro de todos os itens
            # Abordagem: reconstrói a treeview a partir do self.table_ips
            if hasattr(self, 'table_ips') and self.table_ips:
                # Coleta dados dos itens visíveis
                visible_items = {}
                for item_id in all_item_ids:
                    values = self.tree.item(item_id, 'values')
                    visible_items[item_id] = values
                
                # Limpa a treeview completamente
                self.tree.delete(*self.tree.get_children())
                
                # Reinsere todos os itens em ordem de IP
                for ip_addr, item_id in sorted(self.table_ips.items()):
                    # Tenta recuperar os valores originais
                    if item_id in visible_items:
                        values = visible_items[item_id]
                        self.tree.insert("", tk.END, iid=item_id, values=values)

    def _update_table(self, items):
        """Substitui a tabela inteira (mantido para compatibilidade)"""
        self.tree.delete(*self.tree.get_children())
        for item in items:
            self.tree.insert("", tk.END, values=(
                item["num"],
                item.get("status", ""),
                item["ip"],
                item["mac"],
                item.get("nome", ""),
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item.get("servicos", ""),
                item["ping"],
                item.get("grafico", ""),
                item.get("historico", "")
            ))


def main():
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
