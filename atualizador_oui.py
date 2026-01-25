#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATUALIZADOR DE BASE OUI
═════════════════════════════════════════════════════════════════════════════

Módulo para carregar e atualizar a base de dados de OUI (Organizationally Unique
Identifier) a partir de fontes online, mantendo cache local persistente.

FUNCIONALIDADES:
  ✓ Carrega OUI database de múltiplas fontes online
  ✓ Parse de arquivo OUI padrão do IEEE
  ✓ Cache local em JSON para acesso rápido
  ✓ Atualização automática ou manual
  ✓ Fallback para base local se não conseguir conectar
  ✓ Merge inteligente com dados locais customizados

FONTES DE DADOS:
  1. IEEE OUI Database (oficial)
     https://standards.ieee.org/products-services/regauth/oui/public.txt
  
  2. Wireshark OUI Database
     https://www.wireshark.org/download/automated/data/manuf
  
  3. GitHub MAC Lookup Database
     https://raw.githubusercontent.com/TANCODER7/mac-address-lookup/main/database.json

VERSÃO: 1.0
DATA: Janeiro 2026
AUTOR: CMaker Projects

═════════════════════════════════════════════════════════════════════════════
"""

import os
import json
import re
import sys
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from pathlib import Path

# Tenta importar urllib3, caso não esteja disponível
try:
    import urllib.request
    import urllib.error
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False
    print("[WARN] urllib não disponível - modo offline")


class AtualizadorOUI:
    """Gerenciador de atualização e cache de banco de dados OUI"""
    
    # Arquivos de cache
    ARQUIVO_CACHE_OUI = "oui_database.json"
    ARQUIVO_METADATA = "oui_metadata.json"
    
    # URLs de fontes online
    URLS_OUI = [
        "https://standards.ieee.org/products-services/regauth/oui/public.txt",
        "https://www.wireshark.org/download/automated/data/manuf",
        "https://raw.githubusercontent.com/TANCODER7/mac-address-lookup/main/database.json",
    ]
    
    # Intervalo de atualização automática (em horas)
    INTERVALO_ATUALIZACAO = 168  # 1 semana
    
    def __init__(self, diretorio_base: str = "."):
        """Inicializa o atualizador"""
        self.diretorio = Path(diretorio_base)
        self.caminho_cache = self.diretorio / self.ARQUIVO_CACHE_OUI
        self.caminho_metadata = self.diretorio / self.ARQUIVO_METADATA
        self.oui_database = {}
        self.metadata = self._carregar_metadata()
    
    def _carregar_metadata(self) -> Dict:
        """Carrega metadados da última atualização"""
        if self.caminho_metadata.exists():
            try:
                with open(self.caminho_metadata, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[WARN] Erro ao carregar metadata: {e}")
        
        return {
            "ultima_atualizacao": None,
            "fonte": "local",
            "total_ouis": 0,
            "versao": "1.0"
        }
    
    def _salvar_metadata(self):
        """Salva metadados de atualização"""
        try:
            with open(self.caminho_metadata, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[WARN] Erro ao salvar metadata: {e}")
    
    def _precisa_atualizar(self) -> bool:
        """Verifica se precisa atualizar a base"""
        if not self.metadata.get("ultima_atualizacao"):
            return True
        
        try:
            ultima = datetime.fromisoformat(self.metadata["ultima_atualizacao"])
            intervalo = timedelta(hours=self.INTERVALO_ATUALIZACAO)
            return datetime.now() > (ultima + intervalo)
        except Exception:
            return True
    
    def carregar_oui_local(self) -> Dict[str, Tuple[str, str]]:
        """Carrega banco de dados OUI do cache local"""
        if self.caminho_cache.exists():
            try:
                with open(self.caminho_cache, 'r', encoding='utf-8') as f:
                    dados = json.load(f)
                    # Converte de volta para o formato esperado
                    oui_database = {}
                    for oui, info in dados.items():
                        if isinstance(info, list) and len(info) >= 2:
                            oui_database[oui] = (info[0], info[1])
                        elif isinstance(info, dict):
                            oui_database[oui] = (info.get("fabricante", ""), info.get("tipo", ""))
                        elif isinstance(info, str):
                            oui_database[oui] = (info, "")
                    
                    self.oui_database = oui_database
                    print(f"[OK] Carregados {len(oui_database)} OUIs do cache local")
                    return oui_database
            except Exception as e:
                print(f"[ERRO] Erro ao carregar cache: {e}")
        
        return {}
    
    def _fazer_download(self, url: str) -> Optional[str]:
        """Faz download de arquivo de URL"""
        if not URLLIB_AVAILABLE:
            return None
        
        try:
            print(f"[INFO] Baixando de {url}...")
            with urllib.request.urlopen(url, timeout=10) as resposta:
                conteudo = resposta.read().decode('utf-8', errors='ignore')
                print(f"[OK] Download de {len(conteudo)} bytes concluído")
                return conteudo
        except urllib.error.URLError as e:
            print(f"[WARN] Erro de conexão: {e}")
        except urllib.error.HTTPError as e:
            print(f"[WARN] Erro HTTP: {e}")
        except Exception as e:
            print(f"[WARN] Erro no download: {e}")
        
        return None
    
    def _parse_ieee_format(self, conteudo: str) -> Dict[str, Tuple[str, str]]:
        """Parse do formato IEEE OUI (public.txt)"""
        oui_dict = {}
        linhas = conteudo.split('\n')
        
        for linha in linhas:
            linha = linha.strip()
            
            # Pula comentários e linhas vazias
            if not linha or linha.startswith('#'):
                continue
            
            # Formato: "00-12-3F   (hex)  Motorola Mobility Inc"
            match = re.match(r'^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$', 
                           linha, re.IGNORECASE)
            
            if match:
                oui = f"{match.group(1).upper()}:{match.group(2).upper()}:{match.group(3).upper()}"
                fabricante = match.group(4).strip()
                oui_dict[oui] = (fabricante, "")
        
        return oui_dict
    
    def _parse_wireshark_format(self, conteudo: str) -> Dict[str, Tuple[str, str]]:
        """Parse do formato Wireshark (manuf)"""
        oui_dict = {}
        linhas = conteudo.split('\n')
        
        for linha in linhas:
            linha = linha.strip()
            
            # Pula comentários e linhas vazias
            if not linha or linha.startswith('#'):
                continue
            
            # Formato: "00:12:3F  Motorola Inc." ou "00:12:3F Motorola Inc."
            # Ou: "00:12:3F/24 Motorola Inc."
            
            # Remove a máscara de CIDR se existir
            if '/' in linha:
                linha = linha.split('/')[0] + ' ' + ' '.join(linha.split()[1:])
            
            # Divide por espaços múltiplos ou tabs
            partes = re.split(r'[\t\s]+', linha, maxsplit=1)
            
            if len(partes) >= 2:
                oui = partes[0].upper()
                fabricante = partes[1].strip()
                
                # Valida o formato OUI (XX:XX:XX ou XXXXXX)
                if re.match(r'^([0-9A-F]{2}:){2}[0-9A-F]{2}$', oui):
                    oui_dict[oui] = (fabricante, "")
                elif re.match(r'^[0-9A-F]{6}$', oui):
                    # Converte de XXXXXX para XX:XX:XX
                    oui = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"
                    oui_dict[oui] = (fabricante, "")
        
        return oui_dict
    
    def _parse_json_format(self, conteudo: str) -> Dict[str, Tuple[str, str]]:
        """Parse de formato JSON"""
        try:
            dados = json.loads(conteudo)
            oui_dict = {}
            
            if isinstance(dados, dict):
                for oui, info in dados.items():
                    oui = oui.upper()
                    if isinstance(info, dict):
                        fabricante = info.get("manufacturer", info.get("fabricante", ""))
                    else:
                        fabricante = str(info)
                    
                    if re.match(r'^([0-9A-F]{2}:){2}[0-9A-F]{2}$', oui):
                        oui_dict[oui] = (fabricante, "")
            
            return oui_dict
        except json.JSONDecodeError:
            return {}
    
    def atualizar_online(self, forcar: bool = False) -> bool:
        """
        Tenta atualizar a base OUI a partir de fontes online.
        
        Args:
            forcar (bool): Força atualização mesmo se não for necessária
        
        Returns:
            bool: True se atualização bem-sucedida, False caso contrário
        """
        if not forcar and not self._precisa_atualizar():
            print("[INFO] Base OUI atualizada recentemente, pulando atualização")
            return True
        
        if not URLLIB_AVAILABLE:
            print("[WARN] urllib não disponível - usando cache local")
            self.carregar_oui_local()
            return False
        
        oui_database = {}
        fonte_sucesso = None
        
        # Tenta cada URL
        for url in self.URLS_OUI:
            print(f"\n[INFO] Tentando fonte: {url}")
            conteudo = self._fazer_download(url)
            
            if not conteudo:
                continue
            
            # Detecta formato e faz parse
            if "public.txt" in url:
                oui_novo = self._parse_ieee_format(conteudo)
            elif "manuf" in url:
                oui_novo = self._parse_wireshark_format(conteudo)
            elif ".json" in url:
                oui_novo = self._parse_json_format(conteudo)
            else:
                # Tenta detectar automaticamente
                if '{' in conteudo[:100]:
                    oui_novo = self._parse_json_format(conteudo)
                elif '(hex)' in conteudo:
                    oui_novo = self._parse_ieee_format(conteudo)
                else:
                    oui_novo = self._parse_wireshark_format(conteudo)
            
            if oui_novo:
                oui_database = oui_novo
                fonte_sucesso = url
                print(f"[OK] Parsed {len(oui_novo)} OUIs da fonte")
                break
        
        if not oui_database:
            print("[WARN] Nenhuma fonte online conseguiu fornecer dados")
            self.carregar_oui_local()
            return False
        
        # Carrega dados locais customizados
        dados_locais = self.carregar_oui_local()
        
        # Merge: dados online + dados locais customizados
        for oui, info in dados_locais.items():
            if oui not in oui_database:
                oui_database[oui] = info
        
        # Salva novo banco
        self._salvar_oui_local(oui_database)
        
        # Atualiza metadata
        self.metadata.update({
            "ultima_atualizacao": datetime.now().isoformat(),
            "fonte": fonte_sucesso,
            "total_ouis": len(oui_database),
            "versao": "1.0"
        })
        self._salvar_metadata()
        
        self.oui_database = oui_database
        print(f"\n[OK] Base OUI atualizada com sucesso!")
        print(f"    Total de OUIs: {len(oui_database)}")
        print(f"    Fonte: {fonte_sucesso}")
        print(f"    Última atualização: {self.metadata['ultima_atualizacao']}")
        
        return True
    
    def _salvar_oui_local(self, oui_database: Dict[str, Tuple[str, str]]):
        """Salva banco de dados OUI em arquivo local"""
        try:
            # Converte para formato JSON-serializable
            dados_json = {}
            for oui, (fabricante, tipo) in oui_database.items():
                dados_json[oui] = {
                    "fabricante": fabricante,
                    "tipo": tipo if tipo else ""
                }
            
            with open(self.caminho_cache, 'w', encoding='utf-8') as f:
                json.dump(dados_json, f, indent=2, ensure_ascii=False)
            
            print(f"[OK] Salvos {len(oui_database)} OUIs em {self.caminho_cache}")
        except Exception as e:
            print(f"[ERRO] Erro ao salvar cache: {e}")
    
    def obter_oui_database(self, atualizar: bool = False) -> Dict[str, Tuple[str, str]]:
        """
        Obtém o banco de dados OUI.
        
        Args:
            atualizar (bool): Tenta atualizar a partir de fontes online
        
        Returns:
            Dict: Banco de dados OUI {OUI: (Fabricante, Tipo)}
        """
        if not self.oui_database:
            if atualizar:
                self.atualizar_online()
            else:
                self.carregar_oui_local()
        
        return self.oui_database
    
    def adicionar_oui_customizado(self, oui: str, fabricante: str, tipo: str = ""):
        """Adiciona um OUI customizado ao banco de dados local"""
        # Normaliza OUI
        oui = oui.upper()
        if ":" not in oui and len(oui) == 6:
            oui = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"
        
        self.oui_database[oui] = (fabricante, tipo)
        self._salvar_oui_local(self.oui_database)
        print(f"[OK] OUI customizado adicionado: {oui} - {fabricante}")


def main():
    """Função principal para testes e uso direto"""
    print("╔═════════════════════════════════════════════════════════════════╗")
    print("║           ATUALIZADOR DE BASE OUI - TESTE                       ║")
    print("╚═════════════════════════════════════════════════════════════════╝\n")
    
    import argparse
    
    parser = argparse.ArgumentParser(description="Atualizar base de dados OUI")
    parser.add_argument("-u", "--update", action="store_true", 
                       help="Força atualização da base online")
    parser.add_argument("-f", "--force", action="store_true",
                       help="Mesmo que --update")
    parser.add_argument("-l", "--local", action="store_true",
                       help="Carrega apenas do cache local")
    parser.add_argument("-a", "--add", nargs=3, metavar=("OUI", "FABRICANTE", "TIPO"),
                       help="Adiciona um OUI customizado")
    
    args = parser.parse_args()
    
    # Cria atualizador
    atualizador = AtualizadorOUI()
    
    if args.add:
        atualizador.adicionar_oui_customizado(args.add[0], args.add[1], args.add[2])
        return
    
    # Carrega/atualiza banco de dados
    if args.local:
        oui_db = atualizador.carregar_oui_local()
    else:
        atualizador.atualizar_online(forcar=args.update or args.force)
        oui_db = atualizador.oui_database
    
    # Exibe estatísticas
    print(f"\n[INFO] Estatísticas do banco de dados:")
    print(f"       Total de OUIs: {len(oui_db)}")
    
    # Agrupa por fabricante
    fabricantes = {}
    for oui, (fab, tipo) in oui_db.items():
        if fab not in fabricantes:
            fabricantes[fab] = 0
        fabricantes[fab] += 1
    
    print(f"       Total de fabricantes: {len(fabricantes)}")
    print(f"\n[INFO] Top 10 fabricantes:")
    
    for fab, count in sorted(fabricantes.items(), key=lambda x: -x[1])[:10]:
        print(f"       {fab:<40} {count:>3} OUIs")
    
    # Alguns exemplos
    print(f"\n[INFO] Exemplos de OUIs:")
    exemplos = ["24:4B:03", "00:1A:7D", "00:1F:F3", "00:0F:33"]
    for oui in exemplos:
        if oui in oui_db:
            fab, tipo = oui_db[oui]
            print(f"       {oui} -> {fab}")
        else:
            print(f"       {oui} -> Não encontrado")
    
    print("\n[OK] Teste concluído!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[WARN] Programa interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERRO] Erro não tratado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
