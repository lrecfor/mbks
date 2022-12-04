import socket
from _thread import *
import os
import shutil
import hashlib
import users as u

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
                if len(line) > 1:
                    if self.user.log == line.split()[0] and passwd == line.split()[1]:
                        return True
        self.connection.send("Error: password is incorrect.\nPassword: ".encode())
        return False

    def check_status(self):
        with open('admins.txt', 'r') as f:
            logins = f.read().split()
        if self.user.log in logins:
            self.user.status = u.Status.admin
        else:
            self.user.status = u.Status.ordinary

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
        self.check_status()
        print(self.user.log + ': ' + 'status -', self.user.status)
        self.create_directory()
        return True

    def create_directory(self):
        path = os.getcwd() + "/D/" + self.user.log + "/home"
        self.user.path = os.getcwd() + "/D/" + self.user.log
        self.user.dir = os.getcwd() + "/D/" + self.user.log + "/home"
        try:
            os.makedirs(path)
        except OSError:
            pass

    def del_directory(self):
        try:
            shutil.rmtree(self.user.path, ignore_errors=True)
        except OSError:
            pass

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
                string = 'Error: command ' + command_name + ' not found.\n'
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

    def ls(self, command_string):
        if len(list(command_string.split())) == 1:
            dir_name = self.user.dir
        else:
            command_string = command_string[2:]
            dir_name = ' '.join(command_string.split())
            print(dir_name)
        files = os.listdir(dir_name)
        files_list = ''
        for file in files:
            files_list += file + ' '
        files_list += '\n'
        if len(files_list) == 0:
            files_list = '(empty)\n'
        self.connection.send(str.encode(files_list))

    def write(self, command_string):
        amount_received = 0
        if not command_string.split()[2].isdigit():
            print("Error: something wrong with received data.\n")
            self.connection.send(str.encode("Error: something wrong with received data.\n"))
            return False
        else:
            self.connection.send(str.encode("Ok"))
        amount_expected = int(command_string.split()[2])
        file_name = str(self.user.dir + '/' + command_string.split()[1])
        with open(file_name, "w") as f:
            while amount_received < amount_expected:
                try:
                    text_rec = self.connection.recv(2048).decode('utf-8')
                except UnicodeDecodeError:
                    text_rec = ''
                amount_received += len(text_rec)
                if not text_rec and amount_received != amount_expected:
                    print("Error: data was corrupted\n")
                    with open(file_name, "wb"):
                        pass
                    return False
                f.write(str(text_rec))
        return True

    def read(self, command_string):
        if len(list(command_string.split())) > 2:
            command_string = command_string[5:]
            file_name = ' '.join(command_string.split())
        else:
            file_name = command_string.split()[1]
            if file_name[1] != ':':
                file_name = self.user.dir + '\\' + file_name
        try:
            with open(file_name, 'r') as f:
                text = f.read()
        except IOError:
            self.connection.send(str.encode('Error: incorrect file name.\n'))
            return False
        self.connection.send(str.encode(str(len(text))))
        while len(text) > 0:
            self.connection.send(str.encode(text[:1024] + "\n"))
            text = text[1024:]

    # admins functions
    def useradd(self):
        new_user = u.User()
        self.connection.send("Login: ".encode())
        new_user.log = self.connection.recv(1024).decode()
        with open("passwords.txt", 'r') as f:
            logins = f.read()
            if new_user.log in logins.split():
                self.connection.send("Error: user ia already exist.\n".encode())
                return False
        self.connection.send("Password: ".encode())
        new_user.passwd = self.connection.recv(1024).decode()
        with open("passwords.txt", 'a') as f:
            hashed_passwd = hashlib.sha256(new_user.passwd.encode('utf-8')).hexdigest()
            f.write(str('\n' + new_user.log + ' ' + hashed_passwd))
        # create directory
        path = os.getcwd() + "/D/" + new_user.log + "/home"
        new_user.path = os.getcwd() + "/D/" + new_user.log
        new_user.dir = os.getcwd() + "/D/" + new_user.log + "/home"
        os.makedirs(path)
        self.connection.send(str(new_user.log + " was created successfully.\n").encode())

    def userdel(self, user_log):
        print(user_log)
        if user_log == self.user.log:
            self.connection.send("Error: suicide is prohibited on the territory of the Russian Federation\n".encode())
            return False
        with open("sessions.txt", 'r') as f:
            logins = f.read().split()
        if user_log in logins:
            self.connection.send("Error: cannot delete user while he is logged in\n".encode())
        else:
            try:    #delete directory
                shutil.rmtree(str("C:/Users/Дана Иманкулова/projects/python/mbks/D"
                                  + "/" + user_log), ignore_errors=True)
            except OSError:
                pass
        with open("passwords.txt", 'r+') as f:
            lines = f.readlines()
            lines = [lines[i] for i in range(len(lines)) if user_log not in lines[i]]
        with open("passwords.txt", 'w') as f:
            f.writelines(lines)
        self.connection.send(str(user_log + " was deleted successfully.").encode())

    def passwd(self, user_log):
        self.connection.send("Enter new password: ".encode())
        new_passwd = self.connection.recv(1024).decode()
        self.connection.send("Retype new password: ".encode())
        re_new_passwd = self.connection.recv(1024).decode()
        if new_passwd != re_new_passwd:
            self.connection.send("Error: passwords do not match\n".encode())
            return False
        hashed_new_passwd = hashlib.sha256(new_passwd.encode('utf-8')).hexdigest()
        with open("passwords.txt", 'r+') as f:
            lines = f.readlines()
        with open("passwords.txt", 'w') as f:
            for line in lines:
                if user_log in line:
                    line = str(user_log + ' ' + hashed_new_passwd + '\n')
                f.writelines(line)
        self.connection.send("passwd: password updated successfully\n".encode())

    def userinfo(self, user_log=None):
        print(user_log)

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
                    args = len(list(data.decode('utf-8').split()))
                    if args > 3:
                        connection.send(str.encode("Error: text is too big.\n"))
                        continue
                    elif args != 3:
                        connection.send(str.encode("Error: missing argument.\n"))
                        continue
                    else:
                        if not sr.write(data.decode('utf-8')):
                            continue
                elif command == 'read':
                    if len(list(data.decode('utf-8').split())) == 1:
                        connection.send(str.encode("Error: missing file name.\n"))
                        continue
                    else:
                        if not sr.read(data.decode('utf-8')):
                            continue
                elif command == 'help':
                    sr.help(data.decode('utf-8'))
                elif command == 'ls':
                    sr.ls(data.decode('utf-8'))
                elif command == 'logout':
                    sr.logout()
                elif command == 'pwd':
                    sr.pwd()
                elif sr.user.status == u.Status.admin:
                    if command == 'useradd':
                        if len(data.split()) > 1:
                            connection.send("Error: too many arguments\n".encode())
                            continue
                        if not sr.useradd():
                            continue
                    elif command == 'userdel':
                        if len(data.split()) != 2:
                            connection.send("Error: missing argument\n".encode())
                            continue
                        if not sr.userdel(data.decode('utf-8').split()[1]):
                            continue
                    elif command == 'passwd':
                        if len(data.split()) != 2:
                            connection.send("Error: missing argument\n".encode())
                        sr.passwd(data.decode('utf-8').split()[1])
                    elif command == 'userinfo':
                        sr.userinfo(data.decode('utf-8'))
                    else:
                        connection.send(str.encode("Error: command wasn't found.\n"))
                        continue
                else:
                    connection.send(str.encode("Error: command wasn't found.\n"))
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
