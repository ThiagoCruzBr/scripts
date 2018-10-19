# coding: utf-8

### Mascaramento de IPs e Usuarios de um Log de Acesso
# Script para ler os logs (access.log) e mascarar os IPs e Usuarios
# removendo alguns campos nao desejados
# Salva um arquivo com os dados mascarados e outro com a relacao dos usuarios

##### Trecho do Access.log utilizado
# #time_stamp "auth_user" src_ip status_code "req_line" "categories" "rep_level" "media_type" bytes_to_client "user_agent" "virus_name" "block_res"
# [14/Oct/2018:23:59:42 -0300] "joao" 0:0:0:0:0:0:0:0 200 "CONNECT a.wunderlist.com:443 HTTP/1.1" "Interactive Web Applications" "Minimal Risk" "" 492 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" "" "0"
# [14/Oct/2018:23:59:42 -0300] "" 0:0:0:0:0:0:0:0 200 "CONNECT clients6.google.com:443 HTTP/1.1" "Internet Services" "Minimal Risk" "" 851 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" "" "0"
# [14/Oct/2018:23:59:42 -0300] "maria" 10.1.32.186 200 "CONNECT 0.docs.google.com:443 HTTP/1.1" "" "-" "" 1409 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" "" "0"



# Pacotes Usados
import pandas as pd
import numpy as np
import os
# Instale o pacote  apache_log_parser com PIP do Anaconda no Windows atras de proxy
# C:\Users\user\AppData\Local\Continuum\anaconda3\Scripts\pip.exe install apache-log-parser -v --proxy http://<user>:<senha>@<proxy.dominio>:<porta>
import apache_log_parser


# caminho dos logs está no diretório corrente do script
pasta_logs = './' # para uma pasta especifica use : pasta_logs = '/logs'
lista_arquivos = os.listdir(pasta_logs)
lista_arquivos_logs = []

for arquivo in lista_arquivos:
    if arquivo.endswith(".log"):  # Arquivos terminados em .log
        lista_arquivos_logs.append(arquivo)


# Abrindo apenas o primeiro arquivo de logs
f = open(pasta_logs+lista_arquivos_logs[0], 'r')
raw = f.readlines()


# Checando se o parse está lendo corretamente o log
# Passando todos os campos usados no log (datime, user...)
line_parser = apache_log_parser.make_parser("%t \"%u\" %a %s \"%r\" \"%f\" \"%q\" \"%V\" %b \"%{User-Agent}i\" """)
print('### Teste de leitura do log utilizando o parser definido.\n')
print(line_parser(raw[1]))


# Para cada arquivo de log faz o mascaramento e adciona em um unico arquivo
# Cria um dataframe inicial para armazenar os usuários que serão encontrados nos logs
usuario = ["original"]
df_usuario = pd.DataFrame({"usuario_original":np.array(usuario)})
df_usuario["usuario_mascarado"] = "mascarado"
# Contador utilizado para mascarar usuarios. 
# Altere conforme sua necessidade
contador_usuario = 35 

for arquivo_raw in lista_arquivos_logs:
    # Abre o arquivo 
    f = open(pasta_logs+arquivo_raw, 'r')
    raw = f.readlines()
    linhas = len(raw) - 1 # Conta a qtde de linhas 
    eventos_selecionados = [] # cria lista vazia

    print('\n### Mascarando dados do arquivo '+'"'+arquivo_raw+'"')
    for i in range(1, linhas):
        log=line_parser(raw[i])

        # Mascaramento 
		# Nao trata IPv6, neste caso ignora e continua
        try:
            # Mascara IPs (somente IPv4)
			# Altere conforme necessidade
            octeto0 = int(log['remote_ip'].split('.')[0])+3
            octeto1 = int(log['remote_ip'].split('.')[1])+3
            octeto2 = int(log['remote_ip'].split('.')[2])+5
            octeto3 = int(log['remote_ip'].split('.')[3])+1
            IP_mascarado = str(octeto0)+'.'+str(octeto1)+'.'+str(octeto2)+'.'+str(octeto3)

            #### Mascara Usuários
            u_original = log['remote_user']

            # Pesquisa se usuário já encontra-se na tabela
            # Se não existe, adiciona
            checa_usuario = df_usuario.loc[df_usuario['usuario_original'] == u_original]

            if checa_usuario.empty == True:
                # Nao existindo o usuário na tabela, inclua-o e crie usuario mascarado correspondente
                contador_usuario = contador_usuario+1
                u_mascarado = 'User'+str(contador_usuario)
                df_usuario = df_usuario.append({"usuario_original":u_original,"usuario_mascarado":u_mascarado}, ignore_index=True)
                # Salva o usuario mascarado
                

            else:
                # Existindo o usuário na tabela, salva o usuário mascarado correspodente
                u_mascarado = checa_usuario.iloc[0][1]
            ####

			# Faz o parse somente dos eventos desejados e adciona na lista
            dados = log['time_received'], IP_mascarado, u_mascarado, log['request_first_line'], log['filename'], log['query_string']
            eventos_selecionados.append(dados)
                        
        except Exception:
            pass
        

    # Salva lista dos dados mascarados appendando no arquivo
    try:
        nome_arquivo = pasta_logs+'access-mascarado.csv'
        arquivo = open(nome_arquivo, 'a+')
    except FileNotFoundError:
        arquivo = open(nome_arquivo, 'w+')

    # Como a saida da lista contém o caracter " ' "
	# remove-se para não poluir o arquivo de saída  
    for reg in eventos_selecionados:
        arquivo.writelines(','.join(reg) + '\n')
    arquivo.close()

# Salva a relação dos Usuários Originais e Mascarados
print('\n### Gravando a relação de usuários no arquivo "usuarios.csv"')
df_usuario.to_csv(pasta_logs+'usuarios.csv', sep=',', encoding='utf-8', index= False)
    
# Exibe um evento após o mascaramento
print('\n### Teste de leitura de um evento mascarado\n')
print(eventos_selecionados[0])
print('\n')
