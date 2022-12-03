import socket
from _thread import *
import os
import re
import hashlib


count_users = 0
clr_sessions = False


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
        self.connection.send("Error: login doesn't exist\nLogin: ".encode())
        return False

    def check_session(self):
        with open("sessions.txt", 'r') as f:
            logins = f.read().split()
            if self.log not in logins:
                return True
        self.connection.send("Error: you already logged in\nLogin: ".encode())
        return False

    def check_password(self):
        with open("passwords.txt", 'r') as f:
            passwd_hash = hashlib.sha256(self.passwd.encode())
            passwd = passwd_hash.hexdigest()
            for line in f:
                if self.log == line.split()[0] and passwd == line.split()[1]:
                    return True
        self.connection.send("Error: password is incorrect\nPassword: ".encode())
        return False

    def auth(self):
        global count_users
        done = False
        log_checked = False
        passwd_checked = False
        while not done:
            try:
                self.connection.send("Login: ".encode())
                while not log_checked:
                    self.log = self.connection.recv(1024).decode()
                    if not self.check_login():
                        continue
                    if not self.check_session():
                        continue
                    log_checked = True

                self.connection.send("Password: ".encode())
                while not passwd_checked:
                    self.passwd = self.connection.recv(1024).decode()
                    if not self.check_password():
                        continue
                    passwd_checked = True

                with open("sessions.txt", 'a') as f:
                    f.write(self.log + '\n')
                    self.connection.send(str(self.log + ' logged in successfully.\n').encode())
                    count_users += 1
                    done = True
            except WindowsError:
                self.logout('unexpected')
                return False
        return True

    def logout(self, unexpected=None):
        global count_users, clr_sessions
        if count_users != 0:
            count_users -= 1
        if count_users == 0:
            with open('sessions.txt', 'wb'):
                pass
        else:
            with open("sessions.txt", "r") as f:
                file = list(f)
            with open("sessions.txt", "w") as f:
                if str(self.log+'\n') in file:
                    file.remove(self.log+'\n')
                for line in file:
                    f.write(line)
        if unexpected is not None:
            print('Error: lost connection with', self.log)
        else:
            self.connection.send(str(self.log + ' successfully logged out\n').encode())
            print(self.log + ' logged out')


def multi_threaded_client(connection, user):
    print('Connected with', user[1])
    user = User(connection)
    if user.auth():
        while True:
            try:
                data = connection.recv(2048)
                response = 'Server message: ' + data.decode('utf-8') + '\n'
                if not data:
                    user.logout('unexpected')
                    break
                connection.sendall(str.encode(response))
            except WindowsError:
                user.logout('unexpected')
                break
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