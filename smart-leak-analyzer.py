#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
------------------------------------------------------------------------------
 Project: Smart Leak Analyzer (AI-Powered)
 Author: Augusto V.
 Version: 2.0.0
 
 Description:
    Ferramenta avançada de Threat Intelligence que combina a API da Intelligence X
    com LLMs (Large Language Models) para analisar o conteúdo de vazamentos de dados.
    
    A ferramenta busca vazamentos, obtém previews dos arquivos e utiliza IA para
    estruturar dados desorganizados, identificando credenciais comprometidas e PII.

 Features:
    - Integração com IntelX para busca e recuperação de raw data.
    - Integração com OpenAI/OpenRouter para análise semântica de dumps.
    - Extração automática de Credenciais e Hashes via NLP.

 Dependencies:
    pip install requests openai

 Usage:
    export INTELX_KEY="sua-chave"
    export OPENAI_API_KEY="sua-chave"
    python smart_leak_analyzer.py

------------------------------------------------------------------------------
    
DISCLAIMER:
Esta ferramenta foi desenvolvida para fins educacionais e auditorias de segurança autorizadas.
O uso indevido de informações obtidas é de total responsabilidade do usuário.
"""

import os
import sys
import json
import re
import argparse
import requests
from openai import OpenAI

# Cores para terminal (ANSI)
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Configurações de API
INTELX_API_KEY = os.getenv('INTELX_KEY')
INTELX_BASE_URL = 'https://2.intelx.io'

# Configuração Flexível da IA (Suporta OpenAI, OpenRouter, LocalLLM)
LLM_CLIENT = OpenAI(
    api_key=os.getenv('OPENAI_API_KEY'),
    base_url=os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1') # Padrão oficial, mas permite override
)
LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-3.5-turbo') # Modelo padrão

def log(msg, type="info"):
    prefix = {"info": f"[{CYAN}*{RESET}]", "success": f"[{GREEN}+{RESET}]", "error": f"[{RED}-{RESET}]", "warn": f"[{YELLOW}!{RESET}]"}
    print(f"{prefix.get(type, '[*]')} {msg}")

class IntelXService:
    def __init__(self):
        if not INTELX_API_KEY:
            log("Variável INTELX_KEY não configurada.", "error")
            sys.exit(1)
        self.headers = {'x-key': INTELX_API_KEY, 'Content-Type': 'application/json', 'User-Agent': 'Smart-Analyzer/2.0'}

    def search(self, term):
        """Busca o termo na IntelX (focando em vazamentos)."""
        log(f"Buscando vazamentos para: {term}...", "info")
        url = f'{INTELX_BASE_URL}/intelligent/search'
        payload = {
            "term": term,
            "buckets": ["leaks.private.general", "leaks.public.general"],
            "maxresults": 20,
            "sort": 4, # Data decrescente
            "timeout": 5
        }
        try:
            res = requests.post(url, json=payload, headers=self.headers, timeout=10)
            if res.status_code == 200:
                return res.json().get('id')
            log(f"Erro na busca IntelX: {res.status_code}", "error")
        except Exception as e:
            log(f"Exceção IntelX: {e}", "error")
        return None

    def get_results(self, search_id):
        """Lista os metadados dos resultados."""
        url = f'{INTELX_BASE_URL}/intelligent/search/result'
        params = {"id": search_id, "limit": 20, "offset": 0}
        try:
            res = requests.get(url, params=params, headers=self.headers)
            return res.json().get('records', []) if res.status_code == 200 else []
        except Exception:
            return []

    def get_preview(self, item):
        """Tenta obter o texto plano do arquivo vazado."""
        # Tenta preview rápido
        url_prev = f"{INTELX_BASE_URL}/file/preview"
        params = {"did": item.get('did'), "sid": item.get('storageid'), "b": item.get('bucket')}
        
        try:
            res = requests.get(url_prev, params={"did": item.get('did')}, headers=self.headers, timeout=10)
            if res.status_code == 200 and len(res.text) > 10:
                return res.text
            
            # Fallback para View API se Preview falhar
            url_view = f"{INTELX_BASE_URL}/file/view"
            params_view = {"f": 0, "storageid": item.get('storageid'), "bucket": item.get('bucket'), "k": INTELX_API_KEY}
            res_view = requests.get(url_view, params=params_view, headers=self.headers, timeout=15)
            if res_view.status_code == 200:
                return res_view.text
        except Exception:
            pass
        return None

class AIAnalyzer:
    def __init__(self):
        if not os.getenv('OPENAI_API_KEY'):
            log("Variável OPENAI_API_KEY não configurada. A análise IA será pulada.", "warn")
            self.active = False
        else:
            self.active = True

    def analyze_dump(self, content):
        """Usa LLM para estruturar dados de dumps brutos."""
        if not self.active: return None
        
        # Corta o conteúdo para não estourar tokens/custo
        snippet = content[:3000] 
        
        prompt = """
        Você é um Analista de Segurança Sênior. Analise o seguinte trecho de um vazamento de dados (dump).
        Seu objetivo é extrair credenciais e categorizar o risco.
        
        Retorne APENAS um JSON neste formato:
        {
            "risk_level": "High/Medium/Low",
            "summary": "Resumo do que é o arquivo",
            "credentials": [{"email": "...", "password": "...", "hash_type": "..."}]
        }
        
        Se não houver credenciais, retorne lista vazia.
        Conteúdo do Dump:
        """
        
        try:
            completion = LLM_CLIENT.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "Output only valid JSON."},
                    {"role": "user", "content": prompt + "\n" + snippet}
                ],
                temperature=0.2
            )
            raw_response = completion.choices[0].message.content
            # Limpeza básica para garantir JSON
            json_match = re.search(r'({[\s\S]*})', raw_response)
            if json_match:
                return json.loads(json_match.group(1))
        except Exception as e:
            log(f"Erro na análise IA: {e}", "error")
        return None

def main():
    parser = argparse.ArgumentParser(description="Smart Leak Analyzer (IntelX + AI)")
    parser.add_argument("target", help="Domínio, E-mail ou IP para auditar")
    args = parser.parse_args()

    intelx = IntelXService()
    ai = AIAnalyzer()

    # 1. Busca
    sid = intelx.search(args.target)
    if not sid:
        log("Nenhum resultado encontrado ou erro na busca.", "error")
        return

    # 2. Resultados
    records = intelx.get_results(sid)
    log(f"Encontrados {len(records)} registros. Analisando os mais relevantes...", "success")

    for idx, item in enumerate(records[:5]): # Limita a 5 para demonstração
        name = item.get('name', 'Unknown')
        date = item.get('date', 'Unknown')
        
        print(f"\n{'-'*60}")
        log(f"Analisando Arquivo [{idx+1}]: {name} ({date})", "info")
        
        # 3. Download/Preview
        content = intelx.get_preview(item)
        if not content:
            log("Conteúdo inacessível ou vazio.", "warn")
            continue

        print(f"{YELLOW}Preview Raw (primeiros 100 chars): {content[:100]}...{RESET}")

        # 4. Análise IA
        log("Enviando para análise de IA...", "info")
        analysis = ai.analyze_dump(content)
        
        if analysis:
            risk = analysis.get('risk_level', 'Unknown')
            color_risk = RED if risk == 'High' else YELLOW
            print(f"    🔍 Risco: {color_risk}{risk}{RESET}")
            print(f"    📄 Resumo: {analysis.get('summary')}")
            creds = analysis.get('credentials', [])
            if creds:
                print(f"    🔑 Credenciais Identificadas ({len(creds)}):")
                for c in creds:
                    print(f"       - {c.get('email')}:{c.get('password') or c.get('hash_type')}")
        else:
            log("IA não retornou análise estruturada.", "warn")

if __name__ == "__main__":
    print(f"{CYAN}=== Smart Leak Analyzer by Augusto V. ==={RESET}")
    main()