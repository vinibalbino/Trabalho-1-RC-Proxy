import socket
import _thread
import sys
import time
import urllib3
import logging
from logging.handlers import RotatingFileHandler


class LRUCache(object):
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache_data = {}
        self.lru = {}
        self.tm = 0

    def get(self, key):  # se o dado existir no cache,retorna ele,se nao,retorna -1
        "Pegando dados do cache"

        if key in self.cache_data:  # se a chave existe no cache
            # variavel contadora de requisiçoes de dados vai somar 1
            self.lru[key] = self.tm
            self.tm = self.tm + 1
            print("Cached")

            return self.cache_data[key]
        else:
            return -1  # dado nao ta no cache

    def set(self, key, value):  # garantir que n vai atingir a capacidade maxima definida
        # print("Tamanho do cache: {}".format(self.cache_data[key]))
        size_in_bytes = 0
        for c in self.cache_data:
            size_in_bytes += sys.getsizeof(self.cache_data[c])

        # se tiver cheio o cache,vai remover o mais antigo
        if (size_in_bytes + sys.getsizeof(value)) > self.capacity:
            if sys.getsizeof(value) > self.capacity:
                # DAR OUTRO NOME loggingmsg = str(_thread.get_native_id())+"\tHIT FAIL\t"+key #requisição nao esta no cache
                # LOGGER.info(loggingmsg)
                return(print("Não é possivel salvar em cache o pagina pois excede o limite"))
            else:

                old_key = min(self.lru.keys(), key=lambda k: self.lru[k])
                # removendo
                try:
                    # Evicted
                    # loggingmsg = str(_thread.get_native_id())+"\tCACHE FULL\t"+str(self.capacity)
                    # LOGGER.info(loggingmsg)
                    # remove o mais antigo do cache
                    loggingmsg = str(_thread.get_native_id())+"\tEVICT\t"+old_key+"\tEXPIRED" #algo foi expulso do cache 
                    LOGGER.info(loggingmsg) #escreve a variavel no loggging

                    self.cache_data.pop(old_key)
                    self.lru.pop(old_key)  # remove do LRU
                except:
                    print("Não foi possivel remover o cache antigo.")

        else:
            # Salvo no Cache
            
            self.cache_data[key] = value
            self.lru[key] = self.tm
            self.tm = self.tm + 1

            loggingmsg = str(_thread.get_native_id())+"\tADD\t"+key
            LOGGER.info(loggingmsg)
         
        # print("\nLRU: {}\n".format(self.lru))
        # print("\nCache: {}\n".format(self.cache_data))

    def clear_cache(self):
        self.cache_data = {}
        self.lru = {}
        self.tm = 0

    def delete(self, key): 
        if key in self.cache_data:  # se a chave existe no cache
            # variavel contadora de requisiçoes de dados vai somar 1
            self.cache_data.pop(key)
            self.lru.pop(key)
        else:
            print("Não foi possivel deletar")
            
# função abre site e verifica se tem no
def verifica_Cache(url_, c):
    try:
        site_http = url_

        response = open_website(site_http)
        
        verifica = CACHE.get(site_http) 

        if(verifica == -1):
            result = response
            verifica = CACHE.set(site_http, result)
            c.send(result)
            
            # print("Computando")
            # time.sleep(3)
            # return result
        else:
            # Aqui adicionar a variavel de HIT++ pois está no cache
            loggingmsg = str(_thread.get_native_id())+"\tHIT\t"+site_http #requisição esta no cache
            LOGGER.info(loggingmsg)
            c.send(verifica)

    except Exception as Error:
        print("[*] Erro ao verificar/adicionar ao cache: {} ".format(Error))


def open_website(url):
    http = urllib3.PoolManager()
    response = http.request("GET", url)
    return(response.data)


def _generate_headers(response_code):
    """
    Gerando Http headers de volta
    """
    header = ""
    if response_code == 200:
        header += "\n200 HTTP/1.1 OK\n"
    elif response_code == 404:
        header += "501 Not Implemented\n"

    time_now = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    header += "Date: {now}\n".format(now=time_now)
    header += "Server: Simple-Python-Server\n"
    header += "Connection: close\n\n"  # Conexão sera fechada depois da requisição

    return("{}".format(header))


def createServer(client):
    try:

        request = client.recv(1024).decode()  # qq coisa tira decode aq // poe
        request_method = request.split(" ")[0]

        # se url existir no cache,retorne tal informação,se n ::
        if request_method == "GET":
            response_header = _generate_headers(200)
            response = response_header.encode()
            print(response)
        else:
            response_header = _generate_headers(404)
            response = response_header.encode()
            client.send(response)

        # conectando no site
        if request_method == "GET":
            url = request.split(" ")[1]
            if url == "/":
                url = "/index.html"

            print("\n[*]Conectando em: {}\n".format(url))
            # opening_site(url, client)  # função envia site aberto pro cliente

            verifica_Cache(url, client)

            url = request.split("?")[0]

        else:
            print("[*]Requisão HTTP desconhecida\n")

        client.close()

    except Exception as Error:
        print("[*] Erro ao receber mensagem {}".format(Error))
        client.close()


def main():

    global LOGGER, CACHE, PORT, CACHE_SIZE_IN_BYTES, LOG_FILENAME, ALG_CACHE, NREQ, NHITS, NFALTA

    size_args = len(sys.argv)

    if size_args < 9:
        print("Quantidades de argumentos invalidos!\n")
        print(
            "Exemplo: python3 -c <Cache_size> -p <Porta> -l <Nome_do_Arquivo_Log > -a <Algoritmo de cache>"
        )
        sys.exit(-1)

    # --- PASSAGEM DOS VALORES QUE ESTÃO NO PARAMETRO
    i = 1
    while i < 9:
        if sys.argv[i] == "-c":
            CACHE_SIZE_IN_BYTES = int(int(sys.argv[i + 1])*1024)

        if sys.argv[i] == "-p":
            PORT = int(sys.argv[i + 1])

        if sys.argv[i] == "-l":
            LOG_FILENAME = sys.argv[i + 1]

        if sys.argv[i] == "-a":
            ALG_CACHE = sys.argv[i + 1]

        i = i + 1

    LOGGER = logging.getLogger(LOG_FILENAME)
    LOGGER.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_FILENAME, maxBytes=2000, backupCount=5)
    LOGGER.addHandler(handler)

    CACHE = LRUCache(capacity=CACHE_SIZE_IN_BYTES)
    
    try:
        print("[*] Servidor iniciando...")
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        # socket flag
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", PORT))
        print("[*] Ligado a porta %s" % (PORT))

        s.listen(10)
        print("\n[*] Servidor ouvindo conexões\n")

        while True:
            # abre a conexao com o cliente
            try:
                client, addr = s.accept()
                print("\n[*]Conexão no endereço {}\n".format(addr))

                _thread.start_new_thread(createServer, (client,))

            except KeyboardInterrupt:
                s.close()
                print("\n[*] Shutting down...")
                sys.exit(1)

    except Exception as error:
        print("[*] Erro ao fazer o bind: {}".format(error))
        sys.exit(-1)


if __name__ == "__main__":
    main()

# Conversar com o CAUE sobre essas MSG
#  
# loggingmsg = str(_thread.get_native_id())+"\tNUMERO TOTAL DE REQUISIÇÕES\t"+ str(nreq)
# loggingmsg = str(_thread.get_native_id())+"\tNÚMERO TOTAIS DE HITS\t"+ str(nhits)
# loggingmsg = str(_thread.get_native_id())+"\tNÚMERO TOTAIS DE FALTAS\t" + str(nfalta) #nfalta=(nreq-nhits) #FALTAS TOTAIS-> QUANDO ALGUMA REQUISIÇÃO NAO ESTA NO CACHE = NUMERO DE REQUIÇOES TOTAIS,MENOS AS REQUISIÇOES QUE ESTA NO CACHE
# loggingmsg = str(_thread.get_native_id())+"\tTAMANHO MÉDIO DAS PAGINAS DO CACHE\T" +str(nfalta/cache_size)
# loggingmsg = str(_thread.get_native_id())+"\tCHSIZE\t"+cache_size #<identificador> \TAB CHSIZE \TAB old: <oldsize> new: <newsize>
# loggingmsg = str(_thread.get_native_id())+"\tEVICT\t"+url"\tEXPIRED" #algo foi expulso do cache 





"""
s = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
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
