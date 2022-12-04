import socket

ClientMultiSocket = socket.socket()
host = '127.0.0.1'
port = 2004

try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

while True:
    response = ClientMultiSocket.recv(1024).decode('utf-8')

    if response == 'Stop':  # if logout
        ClientMultiSocket.send("Stop".encode())
        ClientMultiSocket.close()
        break

    if response.isdigit():   # read fun, getting text by blocks(1024)
        amount_received = 0
        amount_expected = int(response)
        while amount_received < amount_expected:
            text_rec = ClientMultiSocket.recv(1024)
            amount_received += len(text_rec)
            if not text_rec and amount_received != amount_expected:
                print("Error: data was corrupted\n")
                break
            print(text_rec.decode('utf-8'), end='')

    else:
        print(response, end='')

    message = input()
    if message.split()[0] == 'write':   # write fun, message = (write filename text)
        if len(message.split()) < 3:    # missing argument
            ClientMultiSocket.send(str.encode(message))
            continue
        else:   # if all arguments
            text_sent = ' '.join(message.strip().split()[2:])
            ClientMultiSocket.send(str.encode(message.split()[0] + ' ' +
                                              message.split()[1] + ' ' +
                                              str(len(text_sent))))
            if ClientMultiSocket.recv(1024).decode('utf-8') == 'Ok':
                while len(text_sent) > 0:
                    ClientMultiSocket.send(str.encode(text_sent[:2048]))
                    text_sent = text_sent[2048:]
            else:
                print(response, end='')
        ClientMultiSocket.send(str.encode(input()))
        continue    # return to the start of while

    ClientMultiSocket.send(str.encode(message)) # if message != write, send message(input())

ClientMultiSocket.close()

