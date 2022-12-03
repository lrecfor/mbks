import socket

ClientMultiSocket = socket.socket()
host = '127.0.0.1'
port = 2004

try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

while True:
    res = ClientMultiSocket.recv(1024)
    print(res.decode('utf-8'), end='')
    ClientMultiSocket.send(str.encode(input()))
    if 'out' in res.decode('utf-8').split():
        ClientMultiSocket.close()
ClientMultiSocket.close()

