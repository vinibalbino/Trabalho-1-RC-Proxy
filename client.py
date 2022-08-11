import socket
import sys

#GET http://www.google.com/
#GET http://www.github.com//

HOST = ''

size_args = len(sys.argv)

if size_args < 3:
    print("Quantidades de argument  os invalidos!\n")
    print("Exemplo: python3 -p <Porta> ")
    sys.exit(-1)
    
PORT = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

dest = (HOST, PORT)

s.connect(dest)

url = input("Request: ")
s.send(url.encode())

# Resposta do header, 200 ou 501 ou 404 
print(s.recv(1024).decode('utf-8'))

# Resposta da conexão, o site em si. 
print(s.recv(1024).decode())