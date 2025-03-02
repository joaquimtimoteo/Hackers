# README - Simulação de Verme (Worm) para Estudo e Pesquisa

## Índice
1. Introdução
2. Propósito
3. Requisitos
4. Configuração do Ambiente de Teste
5. Como Executar o Script
6. Funcionalidades Principais
7. Resultados Esperados
8. Limitações
9. Considerações Finais

---

## 1. Introdução

Este script é uma simulação simplificada de um verme (worm), criado exclusivamente para fins educacionais e de pesquisa em segurança cibernética. Ele demonstra como um malware pode se propagar automaticamente entre sistemas em uma rede local, explorando vulnerabilidades conhecidas, como credenciais fracas ou serviços mal configurados.

O script foi desenvolvido para funcionar em ambientes controlados, como laboratórios ou redes isoladas, onde você tenha autorização explícita para realizar testes.

---

## 2. Propósito

O objetivo deste projeto é:
- Demonstrar como worms se propagam em redes locais.
- Explorar diferentes métodos de movimentação lateral, como SSH, SMB (PsExec), RDP e NFS.
- Entender as vulnerabilidades associadas a configurações inadequadas de segurança.
- Aprender como proteger redes contra ataques semelhantes.

---

## 3. Requisitos

### Dependências
Para executar o script, você precisará das seguintes bibliotecas Python:
- `scapy`: Para varredura de rede via ARP.
- `paramiko`: Para conexões SSH.
- `impacket`: Para execução remota via SMB (PsExec) e outras funcionalidades relacionadas ao Windows.

Instale as dependências usando:
```bash
pip install scapy paramiko impacket
```

### Ambiente de Teste
- **Sistema Atacante**: Kali Linux com privilégios de root.
- **Sistemas Alvo**:
  - Um sistema Linux com SSH habilitado (opcional).
  - Um sistema Windows com SMB (porta 445) e RDP (porta 3389) habilitados.
- **Rede Isolada**: Use máquinas virtuais ou contêineres Docker para criar uma rede isolada.

---

## 4. Configuração do Ambiente de Teste

### a. Configurar o Sistema Atacante (Kali Linux)
1. Instale as dependências necessárias:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   pip install scapy paramiko impacket
   ```
2. Execute o script com privilégios de root:
   ```bash
   sudo python3 worm.py
   ```

### b. Configurar o Sistema Alvo (Windows)
1. **Habilitar SMB**:
   - Certifique-se de que o serviço SMB está habilitado.
   - Configure o firewall para permitir conexões na porta `445`:
     ```powershell
     New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
     ```

2. **Habilitar RDP**:
   - Vá para **Painel de Controle > Sistema > Configurações de Sistema Remoto**.
   - Permita conexões remotas via RDP.

3. **Criar Usuário com Credenciais Fracas**:
   - Crie um usuário com senha fraca para facilitar a exploração:
     ```powershell
     net user testuser TestPassword123 /add
     net localgroup administrators testuser /add
     ```

4. **Desativar Proteções Extras (Opcional)**:
   - Desative o UAC (User Account Control) para facilitar a execução remota de comandos.

### c. Configurar o Sistema Alvo (Linux - Opcional)
1. **Habilitar SSH**:
   ```bash
   sudo systemctl start ssh
   sudo systemctl enable ssh
   sudo ufw allow 22/tcp
   sudo ufw reload
   ```

2. **Configurar NFS (Opcional)**:
   ```bash
   sudo apt install nfs-kernel-server
   sudo mkdir -p /export
   sudo chmod 777 /export
   echo "/export *(rw,sync,no_subtree_check)" | sudo tee -a /etc/exports
   sudo exportfs -ra
   sudo systemctl restart nfs-kernel-server
   ```

---

## 5. Como Executar o Script

1. Salve o código fornecido em um arquivo chamado `worm.py`.
2. Abra um terminal no Kali Linux e execute:
   ```bash
   sudo python3 worm.py
   ```
3. Observe os logs gerados pelo script para acompanhar o progresso da propagação.

---

## 6. Funcionalidades Principais

### a. Payload
- Cria um arquivo `infected.txt` no sistema infectado para indicar que o verme foi executado com sucesso.

### b. Varredura de Rede (ARP Scan)
- Detecta hosts ativos na rede local (`192.168.x.x`) usando o protocolo ARP.

### c. Propagação via SSH (Linux)
- Tenta conectar-se aos sistemas alvo via SSH usando credenciais padrão (`kali/12345`).

### d. Propagação via SMB (Windows - PsExec)
- Usa o módulo `psexec` do `impacket` para executar comandos remotamente via SMB (porta `445`).

### e. Propagação via RDP (Windows)
- Tenta executar comandos remotamente via RDP (porta `3389`).

### f. Propagação via NFS (Linux - Opcional)
- Monta compartilhamentos NFS nos sistemas alvo e copia o script do verme para eles.

---

## 7. Resultados Esperados

Com o ambiente configurado corretamente, você deve observar os seguintes resultados:

1. **Criação do Arquivo `infected.txt`**:
   - No sistema atacante: O payload cria o arquivo `infected.txt` localmente.
   - Nos sistemas alvo: O arquivo `infected.txt` será criado nos sistemas comprometidos.

2. **Logs Gerados**:
   - Mensagens detalhadas sobre o progresso do script, incluindo tentativas de conexão e resultados de cada exploração.

3. **Propagação**:
   - O script deve ser capaz de se propagar entre os sistemas alvo, dependendo das configurações e credenciais fornecidas.

---

## 8. Limitações

1. **Compatibilidade**:
   - O script foi projetado para funcionar em ambientes Linux e Windows, mas algumas funcionalidades (como NFS) são específicas do Linux.

2. **Dependência de Credenciais**:
   - A eficácia do script depende de credenciais válidas para os sistemas alvo.

3. **Versão do Impacket**:
   - Versões mais recentes do `impacket` não incluem o módulo `wmiexec`. Substitua-o pelo módulo `psexec`.

4. **Ambiente Controlado**:
   - O script deve ser usado apenas em ambientes autorizados e isolados para evitar danos colaterais.

---

## 9. Considerações Finais

### a. Ética e Legalidade
- Este script deve ser usado **exclusivamente** em ambientes controlados e autorizados.
- Qualquer uso fora dessas condições pode violar leis e regulamentos locais.

### b. Segurança
- Certifique-se de que o ambiente de teste seja completamente isolado da internet e de redes reais.
- Limpe todos os arquivos e registros após os testes para evitar resíduos maliciosos.

### c. Sugestões de Melhoria
- Adicionar mais verificações de segurança antes de executar operações críticas.
- Implementar técnicas de evasão para simular cenários avançados de ataque.
- Expandir o escopo para incluir outras vulnerabilidades, como EternalBlue ou SMB Relay.

---

## 10. Exemplo de Saída

Ao executar o script, você pode ver uma saída semelhante à seguinte:

```
Payload executed: infected.txt created.
Targets found: ['192.168.135.139']
Attempting PsExec lateral movement on 192.168.135.139
PsExec lateral movement succeeded on 192.168.135.139
Attempting RDP exploit on 192.168.135.139
RDP exploit executed on 192.168.135.139
```

No sistema alvo (`192.168.135.139`), o arquivo `infected.txt` será criado no diretório raiz (`C:\`).

---

## 11. Contribuição

Se você deseja contribuir para este projeto, sinta-se à vontade para sugerir melhorias ou adicionar novas funcionalidades. Lembre-se de sempre priorizar a ética e a segurança durante o desenvolvimento.

---

## 12. Disclaimer

Este script é fornecido **sem garantias**. O uso indevido pode causar danos irreparáveis a sistemas não autorizados. O autor não se responsabiliza por qualquer dano resultante do uso inadequado deste código.

Certifique-se de seguir rigorosamente as melhores práticas éticas e legais durante os testes.

---

### Autor: Joaquim Timóteo  
### Data: 03/03/2025  
### Versão: 1.0  
