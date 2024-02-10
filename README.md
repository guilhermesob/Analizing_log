# Analizing_log

# Analizing_log

Este projeto tem como objetivo melhorar suas habilidades de análise de redes, especialmente como engenheiro de redes e segurança da informação. O projeto inclui scripts para análise de logs e pacotes de rede, fornecendo funcionalidades básicas de um SIEM (Security Information and Event Management).

## Funcionalidades

- **Análise de Pacotes TCP/IP:** O script `analistcpip.py` analisa datagramas de pacotes TCP/IP e pode ser integrado a um SIEM para detectar eventos relevantes, como tentativas de conexão não autorizadas e tráfego suspeito.

- **Análise de Logs:** O script `analyze_logs.py` permite a análise de logs de diversas fontes, como aplicações, firewalls, sistemas operacionais, entre outros. Ele interage com a API do OpenAI para gerar respostas automáticas que explicam os logs e detectam atividades maliciosas, como parte do processo de análise.

## Requisitos

- Python 3.x
- Bibliotecas Python: `openai`, `python-dotenv`
  ```
  pip install openai python-dotenv
  ```

## Uso

1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/Analizing_log.git
cd Analizing_log
```

2. Execute o script de análise de pacotes TCP/IP:

```bash
python analistcpip.py
```

3. Execute o script de análise de logs:

```bash
python analyze_logs.py
```

## Configuração da API do OpenAI

- Crie uma conta no [OpenAI](https://platform.openai.com/signup) e obtenha sua chave de API.
- Crie um arquivo `.env` na raiz do projeto e adicione sua chave de API:

```
OPENAI_API_KEY=SuaChaveDeAPIAqui
```

## Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir um pull request ou uma issue com sugestões, correções de bugs ou novos recursos.

## Licença

Este projeto está licenciado sob a [Licença MIT](LICENSE).
