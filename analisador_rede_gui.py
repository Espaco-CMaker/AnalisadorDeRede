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
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import re  # para gráfico e processamento

# Matplotlib para gráficos profissionais
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Reutiliza funções já existentes
try:
    from analisador_rede import (
        obter_interface_ativa,
        fazer_arp_scan,
        calcular_ping,
        obter_info_dispositivo,
        extrair_info_ping,
        obter_netbios
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
        self.table_ips = {}  # {ip: item_id} para rastrear IPs na tabela
        
        # Estado de threads de dispositivos
        self.device_threads = {}  # {ip: thread object}
        self.device_lock = threading.Lock()  # protege acesso ao dicionário

        # Carrega configurações do arquivo
        config = self._load_config()
        
        # Configurações
        self.ping_attempts = tk.IntVar(value=config.get("ping_attempts", 4))
        self.scan_interval = tk.IntVar(value=config.get("scan_interval", 60))  # segundos
        
        # Rastreia alterações para salvar
        self.ping_attempts.trace("w", lambda *args: self._save_config())
        self.scan_interval.trace("w", lambda *args: self._save_config())

        # Ordenação
        self.sort_column = None
        self.sort_reverse = False

        # UI
        self._build_ui()
        
        # Salva configuração ao fechar
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Inicia loop de processamento de fila
        self.root.after(200, self._process_queue)

    # ------------------------------------------------------------------
    # UI
    def _build_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Abas
        self.tab_devices = ttk.Frame(notebook)
        self.tab_config = ttk.Frame(notebook)
        self.tab_logs = ttk.Frame(notebook)

        notebook.add(self.tab_devices, text="Dispositivos")
        notebook.add(self.tab_config, text="Configurações")
        notebook.add(self.tab_logs, text="Logs")

        self._build_devices_tab()
        self._build_config_tab()
        self._build_logs_tab()

    def _build_devices_tab(self):
        top_frame = ttk.Frame(self.tab_devices)
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        self.btn_start = ttk.Button(top_frame, text="Iniciar", command=self.start_scan)
        self.btn_stop = ttk.Button(top_frame, text="Parar", command=self.stop_scan, state=tk.DISABLED)
        self.btn_once = ttk.Button(top_frame, text="Scan agora", command=self.scan_once)

        self.btn_start.pack(side=tk.LEFT, padx=5)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        self.btn_once.pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar(value="Pronto")
        ttk.Label(top_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=15)

        # Tabela com colunas: #, IP, MAC, Hostname, NetBIOS, Fabricante, SO, TTL, Tamanho, Ping, Histórico
        columns = ("num", "ip", "mac", "hostname", "netbios", "fabricante", "so", "ttl", "tamanho", "ping", "historico")
        self.tree = ttk.Treeview(self.tab_devices, columns=columns, show="headings")
        self.tree.heading("num", text="#", command=lambda: self._sort_table("num"))
        self.tree.heading("ip", text="IP", command=lambda: self._sort_table("ip"))
        self.tree.heading("mac", text="MAC Address", command=lambda: self._sort_table("mac"))
        self.tree.heading("hostname", text="Hostname", command=lambda: self._sort_table("hostname"))
        self.tree.heading("netbios", text="NetBIOS", command=lambda: self._sort_table("netbios"))
        self.tree.heading("fabricante", text="Fabricante", command=lambda: self._sort_table("fabricante"))
        self.tree.heading("so", text="SO Detectado", command=lambda: self._sort_table("so"))
        self.tree.heading("ttl", text="TTL", command=lambda: self._sort_table("ttl"))
        self.tree.heading("tamanho", text="Bytes", command=lambda: self._sort_table("tamanho"))
        self.tree.heading("ping", text="Ping", command=lambda: self._sort_table("ping"))
        self.tree.heading("historico", text="Histórico", command=lambda: self._sort_table("historico"))
        
        self.tree.column("num", width=25, anchor="center")
        self.tree.column("ip", width=110, anchor="center")
        self.tree.column("mac", width=120, anchor="center")
        self.tree.column("hostname", width=100, anchor="center")
        self.tree.column("netbios", width=90, anchor="center")
        self.tree.column("fabricante", width=110, anchor="center")
        self.tree.column("so", width=140, anchor="center")
        self.tree.column("ttl", width=30, anchor="center")
        self.tree.column("tamanho", width=50, anchor="center")
        self.tree.column("ping", width=70, anchor="center")
        self.tree.column("historico", width=280, anchor="center")

        vsb = ttk.Scrollbar(self.tab_devices, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0), pady=10)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=10, padx=(0,10))
        
        # Adiciona painel de gráfico à direita com matplotlib
        graph_frame = ttk.LabelFrame(self.tab_devices, text="Gráfico de Ping (Clique em um IP)")
        graph_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=10, pady=10)
        graph_frame.config(width=350)
        
        # Cria figura matplotlib
        self.fig = Figure(figsize=(4.5, 2.8), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.patch.set_facecolor('#f0f0f0')
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Label para informações
        self.graph_info = ttk.Label(graph_frame, text="Selecione um IP para ver o gráfico", justify="center")
        self.graph_info.pack(fill=tk.X, padx=5, pady=5)
        
        # Vincula clique na tabela para mostrar gráfico
        self.tree.bind("<ButtonRelease-1>", self._on_tree_select)
        self.tree.bind("<KeyRelease>", self._on_tree_select)

        # Configura cores para as tags
        self.tree.tag_configure("updating", background="#FFFFCC")  # Amarelo claro para linha sendo atualizada
        self.tree.tag_configure("normal", background="white")

    def _build_config_tab(self):
        frame = ttk.Frame(self.tab_config)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        ttk.Label(frame, text="Tentativas de ping por host:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=1, to=20, textvariable=self.ping_attempts, width=5).grid(row=0, column=1, sticky="w")

        ttk.Label(frame, text="Intervalo entre scans (segundos):").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Spinbox(frame, from_=10, to=900, textvariable=self.scan_interval, width=7).grid(row=1, column=1, sticky="w")

        ttk.Label(frame, text="Dicas:").grid(row=2, column=0, sticky="nw", pady=(15,5))
        dicas = (
            "Use menos tentativas de ping para scans mais rápidos.",
            "Aumente o intervalo para evitar tráfego excessivo.",
            "Execute como administrador para melhor descoberta no Windows.",
        )
        ttk.Label(frame, text="\n".join(dicas), justify="left").grid(row=2, column=1, sticky="w")

    def _build_logs_tab(self):
        self.log_text = tk.Text(self.tab_logs, wrap="word", state=tk.DISABLED, height=25)
        vsb = ttk.Scrollbar(self.tab_logs, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0), pady=10)
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=10, padx=(0,10))

    # ------------------------------------------------------------------
    # Persistência de configurações
    def _load_config(self):
        """Carrega configurações do arquivo config.json"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Erro ao carregar config: {e}")
        return {}
    
    def _save_config(self):
        """Salva configurações no arquivo config.json"""
        try:
            config = {
                "ping_attempts": self.ping_attempts.get(),
                "scan_interval": self.scan_interval.get()
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Erro ao salvar config: {e}")
    
    def _on_closing(self):
        """Chamado ao fechar a janela"""
        self.stop_scan()
        self._save_config()
        self.root.destroy()
    
    def _on_tree_select(self, event=None):
        """Chamado quando um IP é selecionado na tabela"""
        selection = self.tree.selection()
        if selection:
            item_id = selection[0]
            values = self.tree.item(item_id, 'values')
            if len(values) > 1:
                ip_addr = values[1]  # IP está na coluna 1
                self._draw_graph(ip_addr)
    
    def _draw_graph(self, ip_addr):
        """Desenha gráfico visual do histórico de pings com matplotlib"""
        if ip_addr not in self.ping_history or not self.ping_history[ip_addr]:
            self.ax.clear()
            self.ax.text(0.5, 0.5, f"Nenhum dado para {ip_addr}", 
                        ha='center', va='center', transform=self.ax.transAxes)
            self.canvas.draw()
            self.graph_info.config(text=f"Nenhum dado para {ip_addr}")
            return
        
        pings = self.ping_history[ip_addr][-20:]  # últimos 20 pings
        if not pings:
            self.ax.clear()
            self.ax.text(0.5, 0.5, f"Nenhum dado para {ip_addr}", 
                        ha='center', va='center', transform=self.ax.transAxes)
            self.canvas.draw()
            self.graph_info.config(text=f"Nenhum dado para {ip_addr}")
            return
        
        # Limpa o gráfico anterior
        self.ax.clear()
        
        # Estatísticas
        max_ping = max(pings)
        min_ping = min(pings)
        avg_ping = sum(pings) / len(pings)
        
        # Cria índices para o eixo X
        x_vals = list(range(1, len(pings) + 1))
        
        # Desenha a linha principal
        self.ax.plot(x_vals, pings, color='#2196F3', linewidth=2, marker='o', 
                    markersize=6, label='Ping (ms)', markerfacecolor='#2196F3', 
                    markeredgecolor='#1976D2', markeredgewidth=1.5)
        
        # Destaca o último ponto
        if pings:
            self.ax.plot(len(pings), pings[-1], color='#FF5722', marker='o', 
                        markersize=8, markeredgecolor='#E64A19', markeredgewidth=2)
        
        # Linha de média
        self.ax.axhline(y=avg_ping, color='#FFC107', linestyle='--', linewidth=1.5, 
                       label=f'Média: {int(avg_ping)}ms', alpha=0.7)
        
        # Configuração dos eixos
        self.ax.set_xlabel('Número de Amostra', fontsize=9, color='#333')
        self.ax.set_ylabel('Latência (ms)', fontsize=9, color='#333')
        self.ax.set_title(f'Histórico de Ping - {ip_addr}', fontsize=10, fontweight='bold')
        self.ax.grid(True, alpha=0.3, linestyle=':')
        self.ax.set_facecolor('#fafafa')
        self.ax.legend(loc='upper left', fontsize=8)
        
        # Ajusta espaçamento
        self.fig.tight_layout()
        
        # Redesenha o canvas
        self.canvas.draw()
        
        # Atualiza informações
        self.graph_info.config(
            text=f"{ip_addr} | Min: {int(min_ping)}ms | Avg: {int(avg_ping)}ms | Max: {int(max_ping)}ms | Amostras: {len(pings)}"
        )
        
        # Labels dos eixos Y
        y_labels = [
            (canvas_height - margin_bottom, f"{int(min_ping)}ms"),
            (margin_top, f"{int(max_ping)}ms"),
            (canvas_height - margin_bottom - plot_height / 2, f"{int(avg_ping)}ms")
        ]
        
        for y, label in y_labels:
            self.canvas.create_text(margin_left - 5, y, text=label, anchor="e", font=("Arial", 8))
        
        # Atualiza informações
        self.graph_info.config(
            text=f"{ip_addr} | Min: {int(min_ping)}ms | Avg: {int(avg_ping)}ms | Max: {int(max_ping)}ms | Samples: {len(pings)}"
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
        if ip not in self.ping_history or not self.ping_history[ip]:
            return "▪"
        
        # Apenas um indicador visual na tabela
        pings = self.ping_history[ip]
        avg = sum(pings) / len(pings) if pings else 0
        
        if avg < 20:
            return "●●●●● (Excelente)"  # verde
        elif avg < 50:
            return "●●●●○ (Bom)"  # amarelo
        elif avg < 100:
            return "●●●○○ (Ok)"  # laranja
        else:
            return "●●○○○ (Lento)"  # vermelho

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

    def scan_once(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan em andamento", "Espere o scan atual terminar antes de iniciar outro.")
            return
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        """Realiza varredura ARP e lança threads por dispositivo"""
        try:
            self.log("Obtendo interface ativa...")
            ip, mask = obter_interface_ativa()
            if not ip:
                self.log("Nenhuma interface ativa encontrada")
                return
            self.log(f"Interface: {ip} / {mask}")

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
        except Exception as exc:
            self.log(f"Erro no scan: {exc}")

    def _monitor_device(self, num, ip_addr, mac):
        """Thread contínua para monitorar um único dispositivo"""
        tentativas = max(1, self.ping_attempts.get())
        
        # Inicializa histórico se necessário
        if ip_addr not in self.ping_history:
            self.ping_history[ip_addr] = []
        
        # Primeiro, coleta informações gerais (uma vez)
        hostname, fabricante = obter_info_dispositivo(ip_addr, mac)
        ttl, tamanho, so = extrair_info_ping(ip_addr, tentativas=3)
        netbios = obter_netbios(ip_addr)
        
        # Loop contínuo de ping enquanto o dispositivo está ativo
        while not self.stop_event.is_set():
            try:
                # Realiza ping
                ping = calcular_ping(ip_addr, tentativas=tentativas)
                
                # Extrai valor numérico e armazena no histórico
                ms_valor = self._extrair_ms_do_ping(ping)
                if ms_valor is not None:
                    self.ping_history[ip_addr].append(ms_valor)
                    # Mantém apenas os últimos 20 pings
                    if len(self.ping_history[ip_addr]) > 20:
                        self.ping_history[ip_addr].pop(0)
                
                # Gera gráfico com histórico
                historico = self._gerar_grafico_ping(ip_addr)
                
                # Prepara item para a tabela
                item = {
                    "num": num,
                    "ip": ip_addr,
                    "hostname": hostname,
                    "netbios": netbios,
                    "fabricante": fabricante,
                    "so": so,
                    "ttl": str(ttl) if ttl else "N/A",
                    "tamanho": str(tamanho) if tamanho else "N/A",
                    "ping": ping,
                    "historico": historico,
                    "mac": mac
                }
                
                # Envia para fila (atualiza UI)
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
        """Remove a tag de destaque de uma linha"""
        try:
            self.tree.item(item_id, tags=("normal",))
        except:
            pass

    def _add_table_item(self, item):
        """Adiciona ou atualiza um item na tabela, evitando duplicatas"""
        ip_addr = item["ip"].strip()
        
        # Verifica se o IP já existe usando o dicionário de rastreamento
        if ip_addr in self.table_ips:
            # Atualiza a linha existente
            existing_item_id = self.table_ips[ip_addr]
            old_values = self.tree.item(existing_item_id, 'values')
            
            self.tree.item(existing_item_id, values=(
                old_values[0],  # mantém o número original
                item["ip"],
                item["mac"],
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item["so"],
                item["ttl"],
                item["tamanho"],
                item["ping"],
                item["historico"]
            ), tags=("updating",))
            
            # Agenda remover a tag de destaque após 500ms
            self.root.after(500, lambda: self._remove_tag_updating(existing_item_id))
        else:
            # Insere nova linha
            item_id = self.tree.insert("", tk.END, values=(
                item["num"],
                item["ip"],
                item["mac"],
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item["so"],
                item["ttl"],
                item["tamanho"],
                item["ping"],
                item["historico"]
            ), tags=("updating",))
            
            # Registra o IP no dicionário de rastreamento
            self.table_ips[ip_addr] = item_id
            
            # Agenda remover a tag de destaque após 500ms
            self.root.after(500, lambda: self._remove_tag_updating(item_id))

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
            items.append({
                "num": values[0],
                "ip": values[1],
                "hostname": values[2],
                "netbios": values[3],
                "fabricante": values[4],
                "so": values[5],
                "ttl": values[6],
                "tamanho": values[7],
                "ping": values[8],
                "historico": values[9]
            })

        # Define chave de ordenação
        def sort_key(item):
            val = item[col]
            # Tenta converter para número se for ping ou num
            if col in ("ping", "num"):
                try:
                    return float(val.split()[0]) if col == "ping" else int(val)
                except (ValueError, IndexError):
                    return float('inf')
            # Para IP, converte para tupla numérica
            elif col == "ip":
                try:
                    return tuple(int(x) for x in val.split('.'))
                except ValueError:
                    return (0, 0, 0, 0)
            return str(val).lower()

        # Ordena
        items.sort(key=sort_key, reverse=self.sort_reverse)

        # Reinsere na tabela
        self.tree.delete(*self.tree.get_children())
        for item in items:
            self.tree.insert("", tk.END, values=(
                item["num"],
                item["ip"],
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item["so"],
                item["ttl"],
                item["tamanho"],
                item["ping"],
                item["historico"]
            ))

    def _update_table(self, items):
        """Substitui a tabela inteira (mantido para compatibilidade)"""
        self.tree.delete(*self.tree.get_children())
        for item in items:
            self.tree.insert("", tk.END, values=(
                item["num"],
                item["ip"],
                item["hostname"],
                item["netbios"],
                item["fabricante"],
                item["so"],
                item["ttl"],
                item["tamanho"],
                item["ping"],
                item.get("historico", "")
            ))


def main():
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
