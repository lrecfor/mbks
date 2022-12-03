import socket
from _thread import *
import os
import shutil
import re
import hashlib
import user as u

count_users = 0
clr_sessions = False


class Server:

    def __init__(self, connect):
        self.connection = connect
        self.user = u.User()

    def check_login(self):
        with open("passwords.txt", 'r') as f:
            logins = f.read().split()
            if self.user.log in logins:
                return True
        self.connection.send("Error: login doesn't exist.\nLogin: ".encode())
        return False

    def check_session(self):
        with open("sessions.txt", 'r') as f:
            logins = f.read().split()
            if self.user.log not in logins:
                return True
        self.connection.send("Error: you already logged in.\nLogin: ".encode())
        return False

    def check_password(self):
        with open("passwords.txt", 'r') as f:
            passwd_hash = hashlib.sha256(self.user.passwd.encode())
            passwd = passwd_hash.hexdigest()
            for line in f:
                if self.user.log == line.split()[0] and passwd == line.split()[1]:
                    return True
        self.connection.send("Error: password is incorrect.\nPassword: ".encode())
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
                    self.user.log = self.connection.recv(1024).decode()
                    if not self.check_login():
                        continue
                    if not self.check_session():
                        continue
                    log_checked = True

                self.connection.send("Password: ".encode())
                while not passwd_checked:
                    self.user.passwd = self.connection.recv(1024).decode()
                    if not self.check_password():
                        continue
                    passwd_checked = True

                with open("sessions.txt", 'a') as f:
                    f.write(self.user.log + '\n')
                    self.connection.send(str('You logged in successfully.\n').encode())
                    count_users += 1
                    done = True
            except WindowsError:
                self.logout('unexpected')
                return False
        print(self.user.log + ': ' + self.user.log + " logged in successfully.")
        self.create_directory()
        return True

    def create_directory(self):
        path = os.getcwd() + "/D/" + self.user.log + "/home"
        self.user.path = os.getcwd() + "/D/" + self.user.log
        self.user.dir = os.getcwd() + "/D/" + self.user.log + "/home"
        os.makedirs(path)

    def del_directory(self):
        shutil.rmtree(self.user.path, ignore_errors=True)

    def help(self, command_string):
        if len(list(command_string.split())) != 2:
            self.connection.send(
                "Missing command.\nUsage: help [command]\nDisplay information about COMMAND.\n".encode())
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
                string = 'Command ' + command_name + ' not found.\n'
                self.connection.send(string.encode())

    def pwd(self):
        self.connection.send(str.encode(self.user.dir.replace('/', '\\') + '\n'))

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
                if str(self.user.log + '\n') in file:
                    file.remove(self.user.log + '\n')
                for line in file:
                    f.write(line)
        self.del_directory()
        if unexpected is not None:
            print('Error: lost connection with', self.user.log + '.')
        else:
            print(self.user.log + ': ' + self.user.log + ' logged out.')
            self.connection.send(str('You successfully logged out\n'
                                     'Dou you wanna continue with another account? (y/n)\n').encode())
            data = self.connection.recv(2048)
            if data.decode('utf-8')[0] == 'y':
                self.auth()
            else:
                self.connection.send(str("Stop").encode())

    def ls(self, dir_name):
        print(dir_name)
        if len(dir_name.split()) == 1:
            dir_name = self.user.dir
        files = os.listdir(dir_name)
        files_list = ''
        for file in files:
            files_list += file + ' '
        print(files)
        print(files_list)
        self.connection.send(str(files_list + '\n').encode())


def multi_threaded_client(connection, user):
    print('Connected with', user[1])
    sr = Server(connection)
    if sr.auth():
        while True:
            try:
                data = connection.recv(2048)
                if data.decode('utf-8') == 'Stop':
                    break
                print(sr.user.log + ':', data.decode('utf-8'))
                if not data:
                    sr.logout('unexpected')
                    break
                command = data.split()[0].decode('utf-8')
                if command == 'write':
                    connection.send(str.encode(command + '\n'))
                elif command == 'read':
                    connection.send(str.encode(command + '\n'))
                elif command == 'help':
                    sr.help(data.decode('utf-8'))
                elif command == 'ls':
                    sr.ls(data.decode('utf-8'))
                elif command == 'logout':
                    sr.logout()
                elif command == 'pwd':
                    sr.pwd()
                else:
                    connection.send(str.encode("Command wasn't found.\n"))
            except WindowsError:
                sr.logout('unexpected')
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
