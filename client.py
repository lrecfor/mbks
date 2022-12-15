import socket
import codecs

ClientMultiSocket = socket.socket()
host = '127.0.0.1'
port = 2004

try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

login = ''
while True:
    response = ClientMultiSocket.recv(1024).decode('utf-8')

    if 'logged in successfully' in response:
        print(response, end='')
        login = str(response.split()[0] + ': ')

    elif response == 'Login: ' or '(y/n)' in response:
        print(response, end='')
        login = ''

    elif response == 'Stop':  # if logout
        ClientMultiSocket.send("Stop".encode())
        ClientMultiSocket.close()
        break

    elif response.isdigit():
        dec = codecs.getincrementaldecoder('utf8')()
        amount_expected = int(response)
        text_rec = ClientMultiSocket.recv(amount_expected)
        txt = dec.decode(text_rec)
        amount_received = len(txt)
        if amount_received != amount_expected:
            print("Error: data was corrupted")
        else:
            print(txt)
# C:/Users/Дана Иманкулова/projects/python/mbks/1.txt
    else:
        print(response, end='')

    if response == 'New login: ' or 'password: ' in response:
        message = input()
    else:
        message = input(str(login))
    if message.split()[0] == 'write':
        if len(message.split()) < 3:
            ClientMultiSocket.send(str.encode(message))
            continue
        file_name = message.split()[1]
        text = ' '.join(list(message.split()[2:]))
        text_size = str(len(text))
        string = 'write ' + file_name + ' ' + text_size + ' ' + text
        ClientMultiSocket.send(str.encode(string))
        continue
    ClientMultiSocket.send(str.encode(message))

ClientMultiSocket.close()

