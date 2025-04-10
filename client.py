import socket
import threading

nickname = input("Choose a nickname: ")
server_ip = input("Enter server IP (127.0.0.1 for localhost): ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((server_ip, 5555))

udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_message(message):
    if len(message) > 50:
        client.send(message.encode('ascii'))
    else:
        udp_client.sendto(message.encode('utf-8'), (server_ip, 5556))

def receive():
    while True:
        try:
            message = client.recv(1024).decode('ascii')
            if message == 'NICK':
                client.send(nickname.encode('ascii'))
            else:
                print(message)
        except:
            print("An error occurred!")
            client.close()
            break

def write():
    while True:
        message = f'{nickname}: {input("")}'
        send_message(message)

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
