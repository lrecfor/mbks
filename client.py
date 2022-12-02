import socket

ClientMultiSocket = socket.socket()
host = '127.0.0.1'
port = 2004
print('Waiting for connection response')
try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

res = ClientMultiSocket.recv(1024)
while True:
    print(res.decode('utf-8'),end='')
    ClientMultiSocket.send(str.encode(input()))
    res = ClientMultiSocket.recv(1024)
ClientMultiSocket.close()

