import socket
import _thread
import sys
import time
import urllib3
import logging
import datetime

CACHE = {}
LOGGER = {}
PORT = 0
CACHE_SIZE_IN_BYTES = 0
LOG_FILENAME = ""
CONT_REQ = 0
CONT_HITS = 0
OLD_CACHE_SIZE = 0

#Implementação do cache
class LRUCache(object):
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache_data = {}
        self.lru = {}
        self.tm = 0
        self.expires = {}
        self.qtdHits = {}

    def get(self, key):  # se o dado existir no cache,retorna ele,se nao,retorna -1
        "Pegando dados do cache"

        if key in self.cache_data:  # se a chave existe no cache


            self.lru[key] = self.tm
            self.tm = self.tm + 1
            self.qtdHits[key] = self.qtdHits[key] + 1
            print("Cached")

            return self.cache_data[key]
        else:
            return -1

    def set(self, key, value):  # garantir que n vai atingir a capacidade maxima definida

        size_in_bytes = 0
        for c in self.cache_data:
            size_in_bytes += sys.getsizeof(self.cache_data[c])

        # se tiver cheio o cache,vai remover o mais antigo
        if (size_in_bytes + sys.getsizeof(value)) > self.capacity:
            if sys.getsizeof(value) > self.capacity:

                return (print("Não é possivel salvar em cache o pagina pois excede o limite"))
            else:
                while ((size_in_bytes + sys.getsizeof(value)) > self.capacity):

                    if not (self.lru == {}):
                        old_key = min(self.lru.keys(),
                                      key=lambda k: self.lru[k])

                    # removendo
                    if not (self.lru == {}):
                        try:
                            # remove o mais antigo do cache
                            loggingmsg = ""
                            loggingmsg = str(_thread.get_native_id()) + \
                                         "\tEVICT\t" + old_key + "\tCACHE FULL"
                            # escreve a variavel no loggging
                            LOGGER.info(loggingmsg)

                            self.cache_data.pop(old_key)
                            self.lru.pop(old_key)  # remove do LRU
                            self.expires.pop(old_key)

                        except:
                            print("Não foi possivel remover o cache antigo.")

                    size_in_bytes = 0
                    for c in self.cache_data:
                        size_in_bytes += sys.getsizeof(self.cache_data[c])

                # Adicionado
                timeNow = datetime.datetime.now()
                timeNow += datetime.timedelta(minutes=1)
                self.expires[key] = timeNow
                self.cache_data[key] = value
                self.lru[key] = self.tm
                self.tm = self.tm + 1
                self.qtdHits[key] = 0
                # self.qtdHits[key] = self.qtdHits[key] + 1
                return 1

        else:
            # Salvo no Cache
            timeNow = datetime.datetime.now()
            timeNow += datetime.timedelta(minutes=1)

            self.expires[key] = timeNow
            print("Tempo Para Expirar: {}".format(self.expires[key]))

            self.cache_data[key] = value
            self.lru[key] = self.tm
            self.tm = self.tm + 1
            self.qtdHits[key] = 0
            return 1


    def clear_cache(self):
        self.cache_data = {}
        self.lru = {}
        self.tm = 0
        self.expires = {}
        self.qtdHits = {}

        loggingmsg = str(_thread.get_native_id()) + "\tADMIN\tFLUSH\tEVICT\t"
        LOGGER.info(loggingmsg)

    def delete(self, key):
        if key in self.cache_data:  # se a chave existe no cache

            self.expires.pop(key)
            self.cache_data.pop(key)
            self.lru.pop(key)
            self.qtdHits.pop(key)
            print("\n[*]Objeto Deletado: {}\n".format(key))

        else:
            print("Não foi possivel deletar")

    def expire_cache(self, key):

        timeNow = datetime.datetime.now()
        # Tempo de expire:     22/03/2022 10:05
        # Tempo da Requisição: 22/03/2022 10:06
        expireDate = self.expires[key]

        if timeNow > expireDate:
            self.delete(key)
            loggingmsg = str(_thread.get_native_id()) + "\t" + "EVICT" + "\t" + key + "\t Expired"
            LOGGER.info(loggingmsg)

    def dump(self, identifier):
        ALL_size_in_bytes = 0

        loggingmsg = str(_thread.get_native_id()) + \
                     "\t" + " DUMP" + "\t" + " Dump Start"
        LOGGER.info(loggingmsg)

        contForFile = 1

        if identifier == 0:
            for key in self.cache_data:
                ALL_size_in_bytes += sys.getsizeof(self.cache_data[key])

            loggingmsg = str(_thread.get_native_id()) + "\t" + \
                         "DUMP" + "\t" + " Size \t" + str(ALL_size_in_bytes)
            LOGGER.info(loggingmsg)


            for key in self.cache_data:
                itemSize = sys.getsizeof(self.cache_data[key])

                loggingmsg = str(_thread.get_native_id()) + "\tDUMP\t" + "fileid" + \
                             str(contForFile) + "\t " + str(itemSize) + "\t " \
                             + str(self.qtdHits[key]) + "\t " + str(self.expires[key]) + "\t " + str(key)
                LOGGER.info(loggingmsg)

                contForFile = contForFile + 1
                itemSize = 0
                loggingmsg = ""

        elif identifier == 1:
            for key in self.cache_data:
                ALL_size_in_bytes += sys.getsizeof(self.cache_data[key])

            loggingmsg = str(_thread.get_native_id()) + "\tDUMP\t" + \
                         "Size\t" + str(ALL_size_in_bytes)
            LOGGER.info(loggingmsg)

            timeNow = datetime.datetime.now()

            contForFile = 1

            for key in self.cache_data:
                if not (timeNow > self.expires[key]):
                    itemSize = sys.getsizeof(self.cache_data[key])
                    loggingmsg = str(_thread.get_native_id()) + "\t " + "DUMP" + "\t" + "fileid" + str(
                        contForFile) + "\t " + str(itemSize) + "\t " + str(self.qtdHits[key]) + "\t " + str(
                        self.expires[key]) + "\t " + str(key)
                    LOGGER.info(loggingmsg)

                contForFile = contForFile + 1
                itemSize = 0
                loggingmsg = ""

        loggingmsg = str(_thread.get_native_id()) + \
                     "\tDUMP\tDump End"
        LOGGER.info(loggingmsg)
    #Muda a capacidade do cache
    def changeCapacity(self, newCapacity):

        newCapacity = newCapacity * 1024

        if (newCapacity > self.capacity):
            loggingmsg = str(_thread.get_native_id()) + \
                    "\tCHSIZE\t OLD: "+ str(self.capacity/1024) + "\t NEW: " + str(newCapacity/1024) 
            LOGGER.info(loggingmsg)   

            self.capacity = newCapacity
            
        else:
            size_in_bytes = 0
            for url in self.cache_data:
                size_in_bytes += sys.getsizeof(self.cache_data[url])

            while ((size_in_bytes) > newCapacity):
                if not (self.lru == {}):
                    old_key = min(self.lru.keys(), key=lambda k: self.lru[k])

                # removendo
                if not (self.lru == {}):
                    try:

                        # remove o mais antigo do cache
                        loggingmsg = ""
                        loggingmsg = str(_thread.get_native_id()) + \
                                     "\tEVICT\t" + old_key + "\tCACHE FULL"
                        LOGGER.info(loggingmsg)

                        self.cache_data.pop(old_key)
                        self.lru.pop(old_key)  # remove do LRU
                        self.expires.pop(old_key)

                    except:
                        print("Não foi possivel remover o cache antigo.")
                        
                        loggingmsg = str(_thread.get_native_id()) + \
                        "\t[*] Não foi possivel remover o cachef\t" 

                        LOGGER.info(loggingmsg)


                size_in_bytes = 0
                for url in self.cache_data:
                    size_in_bytes += sys.getsizeof(self.cache_data[url])

            loggingmsg = str(_thread.get_native_id()) + \
                    "\tCHSIZE\t OLD: "+ str(self.capacity/1024) + "\t NEW: " + str(newCapacity/1024) 
            LOGGER.info(loggingmsg)   
            self.capacity = newCapacity
            

#Verifica se o url requirido existe no cache ou não
def verifica_Cache(url_, c):
    try:
        site_http = url_

        loggingmsg = ""
        response = open_website(site_http)

        verifica = CACHE.get(site_http)

        if (verifica == -1):
            result = response
            verifica = CACHE.set(site_http, result)
            if verifica == 1:
                loggingmsg = str(_thread.get_native_id()) + "\tADD\t" + site_http
                LOGGER.info(loggingmsg)

                c.send(result)
            else:
                print("[*] Não possivel adicionar")
                loggingmsg = str(_thread.get_native_id()) + \
                 "\t[*] Não foi possivel adicionar\t"
                LOGGER.info(loggingmsg)

                c.send(result)

        else:

            loggingmsg = str(_thread.get_native_id()) + "\tHIT\t" + \
                         site_http  # requisição esta no cache
            LOGGER.info(loggingmsg)

            global CONT_HITS

            CONT_HITS = CONT_HITS + 1

            c.send(verifica)

    except Exception as Error:
        print("[*] Erro ao verificar/adicionar ao cache: {} ".format(Error))
        loggingmsg = str(_thread.get_native_id()) + \
                 "\t[*] Erro ao verificar/adicionar ao cache\t" + str(CONT_REQ)
        LOGGER.info(loggingmsg)

#abre o site
def open_website(url):
    http = urllib3.PoolManager()
    response = http.request("GET", url)
    return (response.data)


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

    return ("{}".format(header))

#Estatísticas no logg
def dumpStatistics():
    global CONT_REQ, CONT_HITS, CACHE_SIZE_IN_BYTES, CACHE, OLD_CACHE_SIZE

    NFaltas = CONT_REQ - CONT_HITS

    loggingmsg = str(_thread.get_native_id()) + \
                 "\tNUMERO TOTAL DE REQUISIÇÕES\t" + str(CONT_REQ)
    LOGGER.info(loggingmsg)

    loggingmsg = str(_thread.get_native_id()) + \
                 "\tNÚMERO TOTAIS DE HITS\t" + str(CONT_HITS)
    LOGGER.info(loggingmsg)

    loggingmsg = str(_thread.get_native_id()) + \
                 "\tNÚMERO TOTAIS DE FALTAS\t" + str(NFaltas)
    LOGGER.info(loggingmsg)

    cachePageMediumSize = NFaltas / (CACHE.capacity / 1024)

    loggingmsg = str(_thread.get_native_id()) + \
                 "\tTAMANHO MÉDIO DAS PAGINAS DO CACHE\t" + str(cachePageMediumSize)
    LOGGER.info(loggingmsg)

    loggingmsg = str(_thread.get_native_id()) + \
                 "\tCHSIZE\t" + "old:\t" + str(OLD_CACHE_SIZE / 1024) + \
                 "\tnew:\t" + str(CACHE.capacity / 1024)
    LOGGER.info(loggingmsg)

#Tratamento de requisção do cliente
def requestTreatment(client):
    global CACHE, OLD_CACHE_SIZE, CONT_REQ
    try:

        request = client.recv(1024).decode()
        request_method = request.split(" ")[0]

        if request_method == "GET":
            url = request.split(" ")[1]
            if ".com" in url:
                response_header = _generate_headers(200)
                response = response_header.encode()
                client.send(response)
            else:
                response_header = _generate_headers(404)
                response = response_header.encode()
                client.send(response)

        elif request_method != "ADMIN":
            response_header = _generate_headers(404)
            response = response_header.encode()
            client.send(response)

        if request_method == "GET":

            url = request.split(" ")[1]

            if url == "/":
                url = "/index.html"

            if not ("http://" in url):
                url = "http://" + url

            if "if-modified-since" in request:
                CACHE.expire_cache(url)

            if ".com" in url:
                print("\n[*]Conectando em: {}\n".format(url))

                verifica_Cache(url, client)

                CONT_REQ = CONT_REQ + 1
                loggingmsg = str(_thread.get_native_id()) + \
                            "\tNUMERO TOTAL DE REQUISIÇÕES\t" + str(CONT_REQ)
                LOGGER.info(loggingmsg)

                url = request.split("?")[0]
            else:
                loggingmsg = str(_thread.get_native_id()) + \
                            "\t[*]Necessario um HTTP formatado corretamente\t"
                LOGGER.info(loggingmsg)
                client.send("[*] Necessario um HTTP formatado corretamente")
                

        elif request_method == 'ADMIN':
            variavelHTTP = False

            if 'HTTP / 1.1' in request:
                variavelHTTP = True
                
            if variavelHTTP:
                admrequest = request.split(' ')[1]

                if admrequest == 'FLUSH' or admrequest == 'flush':
                    sizeList = request.split()
                    if len(sizeList) >= 6:
                        # Geral
                        response_header = _generate_headers(404)
                        response = response_header.encode()
                        client.send(response)
                        print("\n[*] FORMATO ADMIN INCORRETO\n")
                        loggingmsg = str(_thread.get_native_id()) + \
                        "\t[*] FORMATO ADMIN INCORRETO\t"
                        LOGGER.info(loggingmsg)
                    else:
                        response_header = _generate_headers(200)
                        response = response_header.encode()
                        client.send(response)
                        CACHE.clear_cache()
                        
            
                elif admrequest == 'DELETE':
                    cmd = request.split(' ')[5]

                    if not ("http://" in cmd):
                        cmd = "http://" + cmd

                    response_header = _generate_headers(200)
                    response = response_header.encode()
                    client.send(response)

                    CACHE.delete(cmd)

                        
                    loggingmsg = str(_thread.get_native_id()) + \
                                "\tDELETE\t" + cmd
                    LOGGER.info(loggingmsg)



                elif admrequest == 'INFO' or admrequest == 'info':
                    cmd = request.split(' ')[5]

                    match cmd:
                        case "0":
                            response_header = _generate_headers(200)
                            response = response_header.encode()
                            client.send(response)
                            CACHE.dump(0)
                        case "1":
                            response_header = _generate_headers(200)
                            response = response_header.encode()
                            client.send(response)
                            CACHE.dump(1)
                        case "2":
                            response_header = _generate_headers(200)
                            response = response_header.encode()
                            client.send(response)
                            dumpStatistics()
                        case other:
                            response_header = _generate_headers(404)
                            response = response_header.encode()
                            client.send(response)
                            print('501 NOT IMPLEMENTED')
                            
                elif admrequest == 'CHANGE':
                    #cmd = tamanho que quero mudar
                    cmd = request.split(' ')[5]
                    cmd = int(cmd)
                    response_header = _generate_headers(200)
                    response = response_header.encode()
                    client.send(response)
                    OLD_CACHE_SIZE = CACHE.capacity
                    print("OLD: {}".format(OLD_CACHE_SIZE))
                    CACHE.changeCapacity(cmd)
                    print("NEW: {}".format(CACHE.capacity))
                    # chamar a funçao mudar(cmd)
            else:
                admrequest = request.split(' ')[1]

                if admrequest == 'FLUSH' or admrequest == 'flush':
                    sizeList = request.split() 
                   
                    if len(sizeList) > 2:
                        response_header = _generate_headers(404)
                        response = response_header.encode()
                        client.send(response)
                        print("\n[*] FORMATO ADMIN INCORRETO\n")
                        loggingmsg = str(_thread.get_native_id()) + \
                        "\t[*] FORMATO ADMIN INCORRETO\t"
                    else:
                        response_header = _generate_headers(200)
                        response = response_header.encode()
                        client.send(response)
                        CACHE.clear_cache()

                elif admrequest == 'DELETE':
                    cmd = request.split(' ')[2]

                    if not ("http://" in cmd):
                        cmd = "http://" + cmd

                    CACHE.delete(cmd)

                    response_header = _generate_headers(200)
                    response = response_header.encode()
                    client.send(response)
                    loggingmsg = str(_thread.get_native_id()) + \
                                "\tDELETE\t" + cmd
                    LOGGER.info(loggingmsg)


                elif admrequest == 'INFO' or admrequest == 'info':
                    cmd = request.split(' ')[2]

                    match cmd:
                        case "0":
                            response_header = _generate_headers(200)
                            response = response_header.encode()
                            client.send(response)
                            CACHE.dump(0)
                        case "1":
                            response_header = _generate_headers(200)
                            response = response_header.encode()
                            client.send(response)
                            CACHE.dump(1)
                        case "2":
                            response_header = _generate_headers(200)
                            response = response_header.encode()
                            client.send(response)
                            dumpStatistics()
                        case other:
                            response_header = _generate_headers(404)
                            response = response_header.encode()
                            client.send(response)
                            print('501 NOT IMPLEMENTED')
                            
                elif admrequest == 'CHANGE':
                    #cmd = tamanho que quero mudar
                    cmd = request.split(' ')[2]
                    cmd = int(cmd)
                    print(cmd)
                    response_header = _generate_headers(200)
                    response = response_header.encode()
                    client.send(response)

                    OLD_CACHE_SIZE = CACHE.capacity
                    print("OLD: {}".format(OLD_CACHE_SIZE))
                    CACHE.changeCapacity(cmd)
                    print("NEW: {}".format(CACHE.capacity))
                    # chamar a funçao mudar(cmd)

        else:
            print("[*]Requisão HTTP desconhecida\n")
            loggingmsg = str(_thread.get_native_id()) + \
                            "\t[*]Requisão HTTP desconhecida\t"
            LOGGER.info(loggingmsg)

        client.close()

    except Exception as Error:
        print("[*] Erro ao receber mensagem {}".format(Error))
        client.close()

# inicialização de variáveis e socket
def main():
    global CACHE, LOGGER, PORT, CACHE_SIZE_IN_BYTES, LOG_FILENAME, OLD_CACHE_SIZE

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
            CACHE_SIZE_IN_BYTES = int(int(sys.argv[i + 1]) * 1024)

        if sys.argv[i] == "-p":
            PORT = int(sys.argv[i + 1])

        if sys.argv[i] == "-l":
            LOG_FILENAME = sys.argv[i + 1]

        if sys.argv[i] == "-a":
            ALG_CACHE = sys.argv[i + 1]

        i = i + 1

    LOGGER = logging.getLogger(LOG_FILENAME)
    LOGGER.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_FILENAME, mode='w')
    LOGGER.addHandler(handler)

    CACHE = LRUCache(capacity=CACHE_SIZE_IN_BYTES)

    OLD_CACHE_SIZE = CACHE_SIZE_IN_BYTES / 1024

    try:
        print("[*] Servidor iniciando...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

                _thread.start_new_thread(requestTreatment, (client,))

            except KeyboardInterrupt:
                s.close()
                print("\n[*] Shutting down...")
                sys.exit(1)

    except Exception as error:
        print("[*] Erro ao fazer o bind: {}".format(error))
        sys.exit(-1)


if __name__ == "__main__":
    main()
