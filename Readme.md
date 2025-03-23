# 🔥 Python para Hackers: A Arte da Invasão

Este repositório contém uma coleção de scripts e projetos desenvolvidos para fins educacionais e de pesquisa em segurança cibernética. Cada projeto demonstra técnicas e métodos usados em ambientes controlados (laboratórios ou redes isoladas), sempre com o objetivo de ensinar os fundamentos do hacking ético e da defesa cibernética.

> ⚠️ **Atenção:** Todos os scripts devem ser executados apenas em ambientes autorizados e isolados. O uso indevido deste material pode violar leis e causar danos irreparáveis.

---

## 📑 Índice

1. [Introdução](#introdução)
2. [Propósito](#propósito)
3. [Requisitos e Dependências](#requisitos-e-dependências)
4. [Configuração do Ambiente de Teste](#configuração-do-ambiente-de-teste)
5. [Lista de Scripts e Projetos](#lista-de-scripts-e-projetos)
6. [Como Executar os Scripts](#como-executar-os-scripts)
7. [Exemplos de Saída](#exemplos-de-saída)
8. [Limitações](#limitações)
9. [Contribuição](#contribuição)
10. [Disclaimer](#disclaimer)

---

## 📌 1. Introdução

Este repositório reúne diversos scripts que simulam comportamentos típicos de malware e técnicas de exploração, tais como:
- Propagação de worms 🐛
- Enumeração de DNS e subdomínios 🌐
- Coleta de informações sensíveis (info stealer) 🔍
- Keylogging ⌨️
- Escaneamento de redes e proteção de documentos PDF 📄
- Criação de botnets via SSH 🤖

Cada script foi criado com o intuito de ensinar conceitos fundamentais e avançados de hacking ético, sempre ressaltando a importância da ética e do uso responsável das técnicas.

---

## 🎯 2. Propósito

O objetivo deste repositório é:
- Demonstrar a propagação de worms e a movimentação lateral em redes locais.
- Explorar métodos de exploração e enumeração, como DNS, subdomínios e escaneamento de rede.
- Ensinar técnicas de coleta de informações e monitoramento, por meio de keyloggers e info stealers.
- Desenvolver habilidades na criação de ferramentas para testes de segurança e pentesting.
- Discutir métodos de proteção e estratégias de defesa contra ataques cibernéticos.

---

## 🛠️ 3. Requisitos e Dependências

### 📚 Dependências Gerais

Para executar os scripts, certifique-se de ter o **Python 3** instalado. Algumas bibliotecas comuns utilizadas neste repositório são:

- **scapy:** Varredura de rede via ARP.  
- **paramiko:** Conexões SSH.  
- **impacket:** Execução remota via SMB (PsExec) e outras funcionalidades para ambientes Windows.

Instale as dependências gerais com:
```bash
pip install scapy paramiko impacket
```

### 💻 Ambiente de Teste

- **Sistema Atacante:**  
  Geralmente um ambiente Linux (ex.: Kali Linux) com privilégios de root.
- **Sistemas Alvo:**  
  - Linux com SSH habilitado (opcional).  
  - Windows com SMB (porta 445) e RDP (porta 3389) habilitados.
- **Rede Isolada:**  
  Recomenda-se utilizar máquinas virtuais ou contêineres Docker para criar um ambiente de testes seguro.

---

## ⚙️ 4. Configuração do Ambiente de Teste

### a. Sistema Atacante (Kali Linux)
1. Atualize o sistema e instale as dependências:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   pip install scapy paramiko impacket
   ```
2. Execute os scripts com privilégios de root:
   ```bash
   sudo python3 <nome_do_script>.py
   ```

### b. Sistemas Alvo (Windows e Linux)
- **Windows:**  
  - Habilite SMB e RDP.  
  - Configure o firewall para permitir as portas necessárias.  
  - Crie um usuário com credenciais simples para testes.
- **Linux (Opcional):**  
  - Habilite SSH e, se necessário, configure NFS para compartilhamento.

Consulte a documentação interna de cada projeto para instruções específicas.

---

## 📂 5. Lista de Scripts e Projetos

Este repositório inclui os seguintes scripts:

- **worm.py / worm1.py:**  
  Simulação de verme (worm) que demonstra a propagação em redes locais via ARP, SSH, SMB, RDP e NFS.
  
- **client.py / client(level2).py:**  
  Scripts de cliente para testes de comunicação e propagação.

- **server.py / server(level2).py:**  
  Scripts de servidor que aguardam conexões e coordenam ataques simulados.

- **dns_enum.py:**  
  Script para enumeração de registros DNS, mapeando a infraestrutura de redes alvo.

- **subdomain_enum.py:**  
  Ferramenta para identificação de subdomínios, auxiliando na descoberta de alvos potenciais.

- **info_stealer.py:**  
  Simulação de um info stealer para coleta de informações sensíveis do sistema alvo.

- **keylogger.py:**  
  Implementação de um keylogger para registrar entradas de teclado de forma controlada.

- **network_scaner.py:**  
  Script para escanear a rede local e identificar hosts ativos e serviços em execução.

- **pdf_scaner.py:**  
  Ferramenta para análise e verificação de vulnerabilidades em documentos PDF.

- **protection.py:**  
  Script com técnicas de proteção e detecção de atividades maliciosas.

- **ssh_btonet.py:**  
  Simulação de uma botnet utilizando conexões SSH para propagação e comando.

Além dos scripts, o repositório contém apresentações em formato PPTX (ex.: `DNS_Records_enum+(1).pptx`, `Internet+Worm.pptx`, `PDF+Protection.pptx`, `Subdomain+Enumeration.pptx`, `ssh+botnet.pptx`) que explicam a teoria e a prática por trás de cada técnica.

---

## ▶️ 6. Como Executar os Scripts

1. Escolha o script que deseja testar.  
2. Configure o ambiente de teste conforme descrito na seção anterior.  
3. Execute o script utilizando o comando:
   ```bash
   sudo python3 <nome_do_script>.py
   ```
4. Acompanhe os logs e a saída no terminal para verificar o funcionamento do script.

---

## 💬 7. Exemplos de Saída

Ao executar, por exemplo, o script `worm.py`, você poderá observar uma saída similar a esta:
```
Payload executed: infected.txt created.
Targets found: ['192.168.135.139']
Attempting PsExec lateral movement on 192.168.135.139
PsExec lateral movement succeeded on 192.168.135.139
Attempting RDP exploit on 192.168.135.139
RDP exploit executed on 192.168.135.139
```
Nesse caso, o arquivo `infected.txt` é criado nos sistemas comprometidos, indicando a propagação do worm.

---

## 🚧 8. Limitações

- **Compatibilidade:**  
  Alguns scripts foram desenvolvidos para funcionar em ambientes Linux ou Windows, e nem todas as funcionalidades são multiplataforma.

- **Dependência de Credenciais:**  
  Muitos scripts dependem de credenciais padrão ou configuradas previamente para funcionar corretamente.

- **Versões de Bibliotecas:**  
  Versões recentes de bibliotecas como o `impacket` podem ter alterações. Verifique a documentação de cada script para eventuais adaptações.

- **Ambiente Controlado:**  
  Estes scripts devem ser testados somente em ambientes isolados e autorizados.

---

## 🤝 9. Contribuição

Contribuições são bem-vindas! Se você deseja aprimorar algum script ou adicionar novas funcionalidades:
- Faça um fork do repositório.
- Submeta suas alterações via pull request.
- Mantenha o foco na ética e na segurança.

---

## ⚠️ 10. Disclaimer

Este repositório e todos os scripts nele contidos são fornecidos **sem garantias**.  
**Uso Responsável:**  
- Utilize o material somente em ambientes autorizados e para fins educacionais.  
- O autor não se responsabiliza por qualquer dano decorrente do uso inadequado deste código.

---

### 👤 Autor

**Joaquim Timóteo**  
**Data:** 03/03/2025  
**Versão:** 1.0

