import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import _thread
import urllib.request
import signal
import sys
import time
import threading
import urllib.error
import urllib.request
import urllib.parse


def _generate_headers(response_code):
    """
    Gerando Http headers de volta
    """
    header = ''
    if response_code == 200:
        header += 'ADMIN GET HTTP/1.1 200 OK\n'
    elif response_code == 404:
        header += '501 Not Implemented\n'

    time_now = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    header += 'Date: {now}\n'.format(now=time_now)
    header += 'Server: Simple-Python-Server\n'
    header += 'Connection: close\n\n'  # Conexão sera fechada depois da requisição
    return header

def createServer(client):
    request = client.recv(1024).decode() #qq coisa tira decode aq // poe


    request_method = request.split(' ')[0]

    if request_method == 'GET':
        print('OK')
        url = request.split(' ')[1]
        print("Conectando em: {}".format(url))
        pagina = urllib.request.urlopen(url) #aqui abre o site
        print(pagina.read())
        url = request.split('?')[0]

        if url == "/":
            url = "/index.html"
    else:
        print('Requisão HTTP desconhecida')

    if request_method == 'GET':
        response_header = _generate_headers(200)
        response = response_header.encode()
        client.send(response)
    else:
        response_header = _generate_headers(404)
        response = response_header.encode()
        client.send(response)

    client.close()



def main():

    global PORT, CACHE_SIZE_IN_KB, LOG_FILENAME, ALG_CACHE
    
    size_args = len(sys.argv)

    if size_args < 9:
        print("Quantidades de argumentos invalidos!\n")
        print("Exemplo: python3 -c <cache_size> -p <port> -l <log_file> -a <algoritmo de cache>")
        sys.exit(-1)
        

    # --- PASSAGEM DOS VALORES QUE ESTÃO NO PARAMETRO
    CACHE_SIZE_IN_KB = int(sys.argv[2])
    PORT = int(sys.argv[4])
    LOG_FILENAME = sys.argv[6]
    ALG_CACHE = sys.argv[8]

    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    print("Servidor iniciado")
    # reserva o port

    # socket flag
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', PORT))
    print("Ligado a porta %s" % (PORT))
    # coloca o socket em listen
    s.listen(10)
    print("Servidor ouvindo conexões")

    # loop
    while True:
        # abre a conexao com o cliente
        client, addr = s.accept()
        print('Conexão no endereço', addr)

        _thread.start_new_thread(createServer, (client,))

if __name__ == '__main__':
    main()





"""s = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
s.bind(('localhost',PORT))
s.listen()

print('Agurdando conexão')
conn,ender = s.accept()
print('CONECTADO EM ',ender)


while True:
    data = conn.recv(1024)


    if not data:
        print('Fechando conexão')
        conn.close()
        break
    conn.sendall(data)
"""