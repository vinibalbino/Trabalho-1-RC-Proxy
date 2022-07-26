import socket

#GET http://www.google.com/
#GET http://www.github.com//

HOST = 'localhost'
PORT = 8080

s = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
s.connect(('localhost',PORT))
#se n funcionar,tentar url = str.encode() --> s.sendall(url)
url = input("Request: ")
s.send(url.encode())
header = s.recv(1024) #vou receber algo de la-> HTTP 200 OK (HEADER)
# print('Mensagem ecoada',header.decode())
print(header.decode())

"""
print(s.recv(packagesize).decode('utf-8'))
print(s.recv(packagesize).decode())"""