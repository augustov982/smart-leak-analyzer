# 🧠 Smart Leak Analyzer (AI-Powered)

> **Ferramenta avançada de Threat Intelligence que combina a API da Intelligence X com Inteligência Artificial (LLMs).**

Diferente de scanners comuns que apenas buscam por palavras-chave (Regex), o **Smart Leak Analyzer** utiliza Processamento de Linguagem Natural (NLP) para ler o conteúdo de vazamentos de dados brutos e identificar contextos de risco, credenciais válidas e informações pessoais (PII) com alta precisão.

## 🚀 Diferenciais

- 🤖 **Análise Semântica:** Usa IA (OpenAI/GPT) para entender se um dump contém senhas reais ou apenas logs irrelevantes.
- 🔍 **Busca Profunda:** Conecta-se à Intelligence X para acessar buckets privados e públicos.
- 📄 **Preview Automático:** Tenta ler o conteúdo do arquivo vazado sem necessidade de baixar o arquivo completo.
- 🚦 **Classificação de Risco:** A IA categoriza o achado como "Risco Alto", "Médio" ou "Baixo" automaticamente.

## ⚙️ Instalação

Necessário Python 3+ instalado.

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt

🔐 Configuração das Chaves (OpSec)
Esta ferramenta requer duas chaves de API. Configure-as como variáveis de ambiente para manter a segurança e nunca exponha chaves no código:
Linux / Mac:
export INTELX_KEY="sua-chave-intelx"
export OPENAI_API_KEY="sua-chave-openai"

Windows (Powershell):
$env:INTELX_KEY="sua-chave-intelx"
$env:OPENAI_API_KEY="sua-chave-openai"

💻 Como Usar
O script aceita e-mails, domínios ou IPs como alvo.

python smart-leak-analyzer.py empresa-alvo.com
Exemplo de Saída (Output):
[*] Auditando alvo: empresa-alvo.com
[+] Search ID gerado: xxxxx-xxxxx
[!] ALERTA: Encontrados 3 registros.
    -> Análise IA: Risco ALTO (Credenciais de banco de dados identificadas)
    -> Resumo: Dump de configuração SQL contendo user/pass administrativo.

⚠️ Disclaimer (Aviso Legal)
Esta ferramenta é uma Prova de Conceito (PoC) para demonstrar o uso de IA em Defesa Cibernética.
O uso não autorizado em alvos de terceiros é estritamente proibido. Desenvolvido para Blue Teams e Pesquisadores de Segurança.

👨‍💻 Autor
Desenvolvido por Augusto V.
