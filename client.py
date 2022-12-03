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
    if res.decode('utf-8') == 'Stop':
        ClientMultiSocket.send("Stop".encode())
        ClientMultiSocket.close()
        break
    print(res.decode('utf-8'), end='')
    ClientMultiSocket.send(str.encode(input()))
ClientMultiSocket.close()

