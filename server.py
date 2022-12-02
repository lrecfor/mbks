import socket
from _thread import *
import os
import re
import hashlib


class User:

    def __init__(self, connect):
        self.log = None
        self.passwd = None
        self.connection = connect

    def check_login(self):
        with open("passwords.txt", 'r') as f:
            logins = f.read().split()
            if self.log in logins:
                return True
        self.connection.send("Login doesn't exist\n".encode())
        return False

    def check_session(self):
        with open("sessions.txt", 'r') as f:
            logins = f.read().split()
            if self.log not in logins:
                return True
        self.connection.send("You already logged in\n".encode())
        return False

    def check_password(self):
        with open("passwords.txt", 'r') as f:
            passwd_hash = hashlib.sha256(self.passwd.encode())
            passwd = passwd_hash.hexdigest()
            for line in f:
                if self.log == line.split()[0] and passwd == line.split()[1]:
                    return True
        self.connection.send("Password is incorrect\n".encode())
        return False

    def auth(self):
        done = False
        while not done:
            self.connection.send("Login: ".encode())
            self.log = self.connection.recv(1024).decode()
            if not self.log:
                print('No data from ', self.log)
                break
            if not self.check_login():
                continue
            if not self.check_session():
                continue
            self.connection.send("Password: ".encode())
            self.passwd = self.connection.recv(1024).decode()
            if not self.passwd:
                print('No data from ', self.log)
                break
            if not self.check_password():
                continue
            with open("sessions.txt", 'a') as f:
                f.write(self.log + '\n')
                self.connection.send(str(self.log + ' logged in successfully.\n').encode())
                done = True


def multi_threaded_client(connection, user):
    print('Connected with', user[1])
    user = User(connection)
    user.auth()
    while True:
        data = connection.recv(2048)
        response = 'Server message: ' + data.decode('utf-8')
        if not data:
            print('Lost Connection with', user.log)
            break
        connection.sendall(str.encode(response))
    connection.close()


if __name__ == "__main__":
    ServerSideSocket = socket.socket()
    host = '127.0.0.1'
    port = 2004
    ThreadCount = 0

    try:
        ServerSideSocket.bind((host, port))
    except socket.error as e:
        print(str(e))
    print('Socket is listening..')
    ServerSideSocket.listen(5)

    while True:
        Client, address = ServerSideSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(multi_threaded_client, (Client, address))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSideSocket.close()
