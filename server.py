import socket
from _thread import *
import os
import shutil
import re
import hashlib


count_users = 0
clr_sessions = False


class User:

    def __init__(self, connect):
        self.log = None
        self.passwd = None
        self.connection = connect
        self.path = None
        self.dir = None # /home

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
        self.create_directory()
        return True

    def create_directory(self):
        path = os.getcwd() + "/D/" + self.log + "/home"
        self.path = os.getcwd() + "/D/" + self.log
        self.dir = os.getcwd() + "/D/" + self.log + "/home"
        os.makedirs(path)

    def del_directory(self):
        shutil.rmtree(self.path, ignore_errors=True)

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
        self.del_directory()
        if unexpected is not None:
            print('Error: lost connection with', self.log)
        else:
            print(self.log + ' logged out')
            self.connection.send(str(self.log + ' successfully logged out\n'
                                                'Dou you wanna continue with another account?\n(y/n) ').encode())
            data = self.connection.recv(2048)
            if data.decode('utf-8')[0] == 'y':
                self.auth()
            else:
                self.connection.send(str("Stop").encode())

    def help(self, command_string):
        if len(list(command_string.split())) != 2:
            self.connection.send("Missing command.\nUsage: help [command]\nDisplay information about COMMAND.\n".encode())
        else:
            command_name = command_string.split()[1]
            if command_name == "write":
                self.connection.send("Usage: write [filename] [text]\nPrint TEXT in the file.\n".encode())
            elif command_name == "read":
                self.connection.send("Usage: read [filename]\nRead and display file content.\n".encode())
            elif command_name == "help":
                self.connection.send("Usage: help [command]\nDisplay information about COMMAND.\n".encode())
            elif command_name == "ls":
                self.connection.send("Usage: ls [directory]\nList information about the DIRECTORY.\n".encode())
            elif command_name == "logout":
                self.connection.send("Usage: logout\nLog the user out of a system.\n".encode())
            elif command_name == "pwd":
                self.connection.send("Usage: pwd\nPrint the name of the current working directory.\n".encode())
            else:
                string = 'command ' + command_name + ' not found.\n'
                self.connection.send(string.encode())


def multi_threaded_client(connection, user):
    print('Connected with', user[1])
    user = User(connection)
    if user.auth():
        while True:
            try:
                data = connection.recv(2048)
                if data.decode('utf-8') == 'Stop':
                    break
                print(user.log + ': ', data.decode('utf-8'))
                if not data:
                    user.logout('unexpected')
                    break
                command = data.split()[0].decode('utf-8')
                if command == 'write':
                    connection.sendall(str.encode(command))
                elif command == 'read':
                    connection.sendall(str.encode(command))
                elif command == 'help':
                    user.help(data.decode('utf-8'))
                elif command == 'ls':
                    connection.sendall(str.encode(command))
                elif command == 'logout':
                    user.logout()
                elif command == 'pwd':
                    connection.sendall(str.encode(command))
                else:
                    connection.sendall(str.encode("command wasn't found\n"))
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

    with open('sessions.txt', 'wb'):
        pass
    shutil.rmtree(os.getcwd() + "/D", ignore_errors=True)
    os.mkdir(os.getcwd() + "/D")

    while True:
        Client, address = ServerSideSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(multi_threaded_client, (Client, address))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSideSocket.close()