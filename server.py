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
        self.access_matrix = dict()

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

    def check_groups(self, login):
        with open('groups.txt', 'r') as f:
            lines = f.readlines()
        groups = []
        for line in lines:
            if login in line.split():
                groups.append(line.split()[0][:-1])
        return groups

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
                    self.connection.send(str(self.user.log + ' logged in successfully.\n').encode())
                    count_users += 1
                    done = True
            except WindowsError:
                self.logout('unexpected')
                return False
        print(self.user.log + ': ' + self.user.log + " logged in successfully.")
        self.user.group = self.check_groups(self.user.log)
        self.create_directory()
        return True

    def create_directory(self):
        path = os.getcwd() + "\\D\\" + self.user.log + "\\home"
        self.user.path = os.getcwd() + "\\D\\" + self.user.log
        self.user.dir = os.getcwd() + "\\D\\" + self.user.log + "\\home"
        try:
            os.makedirs(path)
            '''self.set_rights(self, self.user.log, path, 6, "u")
            self.set_rights(self, self.user.log, path, 6, "g")'''
        except OSError:
            pass

    def del_directory(self):
        try:
            shutil.rmtree(self.user.path, ignore_errors=True)
        except TypeError:
            pass

    def set_rights(self, subject_name, object_name, rights, subject_type):
        object_name = object_name.replace("/", "\\")
        self.access_matrix[(subject_name, object_name, subject_type)] = rights
        self.save_rights()

    def get_rights(self, object_name):
        object_name = object_name.replace("/", "\\")
        if self.user.log == "root":
            return str(str(6) + " " + self.user.log + " " + self.user.log + "\n")
        rights_list = list()
        rights = str(self.access_matrix.get((self.user.log, object_name, "u")))
        rights_list.append("".join(list(rights))
                           + " " + self.user.log + " " + self.user.log + "\n")
        if rights == "None":
            return rights_list
        for group in self.check_groups(self.user.log):
            rights = str(self.access_matrix.get((group, object_name, "g")))
            if group == self.user.log and "None" in rights:
                return str("".join(list(rights)) + " " + self.user.log + " " + str(group) + "\n")
            if "None" not in rights:
                rights_list.append("".join(list(rights))
                                   + " " + self.user.log + " " + str(group) + "\n")
        return rights_list

    def check_rights(self, subject_name, object_name, right_type):
        self.check_groups(self, self.user.log)
        if "adm" in self.user.group:
            return True
        object_name = object_name.replace("/", "\\")
        rights = str(self.access_matrix.get((subject_name, object_name, "u")))
        rights_g = str(self.access_matrix.get((subject_name, object_name, "g")))
        if rights == "None" or rights_g == "None":
            return False
        for group in self.check_groups(subject_name):
            rights = str(self.access_matrix.get((group, object_name, "g")))
            if "None" not in rights and rights == right_type:
                return True
        return False

    def update_rights(self):
        self.access_matrix = dict()
        with open('access_matrix.txt', 'r') as f:
            for line in f.readlines():
                line = line.split("|")
                self.access_matrix[(line[0], line[1], line[2])] = int(line[3].replace('\n', ''))

    def delete_rights(self, subject_name):
        with open('access_matrix.txt', 'r') as f:
            lines = f.readlines()
        with open('access_matrix.txt', 'w') as f:
            if "".join(lines[-1:]).split("|")[0] == subject_name:
                lines[-2:] = lines[-2:][0].replace("\n", "")
            for line in lines:
                if line.split("|")[0] != subject_name:
                    f.writelines(line)

    def save_rights(self):
        with open('access_matrix.txt', 'w') as f:
            acc_matr = list(self.access_matrix.items())
            acc_matr = ["|".join(list(["|".join(list(acc_matr[i][0])),
                                                 str(acc_matr[i][1])])) for i in
                             range(len(acc_matr))]
            acc_matr = "\n".join(acc_matr)
            f.write(acc_matr)

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
            elif command_name == "rr":
                self.connection.send("Usage: rr [filename]\nPrint the permissions for the file.\n".encode())
            elif command_name == "chmod":
                self.connection.send("Usage: chmod [filename] [u|g] [subjectName] [rights]\nChange permissions for file.\n".encode())
            else:
                string = 'Error: command ' + command_name + ' not found.\n'
                self.connection.send(string.encode())

    def pwd(self):
        self.connection.send(str.encode("D:\\" + self.user.log + "\\home\\" + '\n'))

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

    # check_rights
    def ls(self, command_string):
        if len(list(command_string.split())) == 1:
            dir_name = self.user.dir
        else:
            command_string = command_string[2:]
            dir_name = ' '.join(command_string.split())
            print(dir_name)
        '''if not self.check_rights(self.user.log, dir_name, 2):
            self.connection.send(str.encode('Error: access denied.\n'))
            return False'''
        files = os.listdir(dir_name)
        files_list = ''
        for file in files:
            files_list += file + ' '
        files_list += '\n'
        if len(files_list) == 0:
            files_list = '(empty)\n'
        self.connection.send(str.encode(files_list))

    # check_rights
    def write(self, command_string):
        amount_expected = command_string.split()[2]
        text = ' '.join(list(command_string.split()[3:]))
        amount_received = len(text)
        if amount_received == amount_expected:
            self.connection.send(str.encode("Error: data was corrupted.\n"))
        else:
            file_name = command_string.split()[1]
            if file_name[1] != ':':
                file_name = str(self.user.dir + '\\' + command_string.split()[1])
            else:
                if "/" in file_name:
                    file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                + "\\".join(file_name.split("/")[1:])
                else:
                    file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(file_name.split("\\")[1:])
            '''if not self.check_rights(self.user.log, file_name, 2):
                self.connection.send(str.encode('Error: access denied.\n'))
                return False
            if not os.path.isfile(file_name) and self.user.log != "root":
                self.set_rights(self.user.log, file_name, 6, "u")
                self.set_rights(self.user.log, file_name, 6, "g")  # user group'''
            with open(file_name, "w") as f:
                f.write(text)
            self.connection.send(str.encode('File was written successfully.\n'))
        return True

    # check_rights
    def read(self, command_string):
        file_name = command_string.split()[1]
        if file_name[1] != ':':
            file_name = self.user.dir + '\\' + file_name
        else:
            if "/" in file_name:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(file_name.split("/")[1:])
            else:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                        + "\\".join(file_name.split("\\")[1:])
        '''if not self.check_rights(self.user.log, file_name, 4):
            self.connection.send(str.encode('Error: access denied.\n'))
            return False'''
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                try:
                    text = f.read()
                except UnicodeDecodeError:
                    self.connection.send(str.encode('UnicodeDecodeError: utf-8 codec can\'t decode.\n'))
                    return False
        except IOError:
            self.connection.send(str.encode('Error: incorrect file name.\n'))
            return False
        self.connection.send(str.encode(str(len(text))))
        self.connection.send(str(text).encode('utf-8'))

    def rr(self, command_string):   # check rights for file rr filename
        command_string = command_string.split()
        file_name = command_string[1]
        if file_name[1] != ':':
            file_name = self.user.dir + '\\' + file_name
        else:
            if "/" in file_name:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(file_name.split("/")[1:])
            else:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(file_name.split("\\")[1:])
        rights = "".join(list(self.get_rights(file_name)))
        self.connection.send(str.encode(rights))

    def chmod(self, command_string):    # chmod filename u|g subjectName rights
        command_string = command_string.split()
        file_name = command_string[1]
        if file_name[1] != ':':
            file_name = self.user.dir + '\\' + file_name
        else:
            if "/" in file_name:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(file_name.split("/")[1:])
            else:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(file_name.split("\\")[1:])
        arg = command_string[2]
        subject_name = command_string[3]
        rights = command_string[4]
        self.set_rights(subject_name, file_name, rights, arg)
        self.connection.send(str.encode("Permissions were updated.\n"))

    # admins functions
    def useradd(self):
        new_user = u.User()
        self.connection.send("New login: ".encode())
        new_user.log = self.connection.recv(1024).decode()
        with open("passwords.txt", 'r') as f:
            logins = f.read()
            if new_user.log in logins.split():
                self.connection.send("Error: user is already exist.\n".encode())
                return False
        self.connection.send("New password: ".encode())
        new_user.passwd = self.connection.recv(1024).decode()
        with open("passwords.txt", 'a') as f:
            hashed_passwd = hashlib.sha256(new_user.passwd.encode('utf-8')).hexdigest()
            f.write(str('\n' + new_user.log + ' ' + hashed_passwd))
        # create directory
        path = os.getcwd() + "\\D\\" + new_user.log + "\\home"
        new_user.path = os.getcwd() + "\\D\\" + new_user.log
        new_user.dir = os.getcwd() + "\\D\\" + new_user.log + "\\home"
        os.makedirs(path)
        self.groupadd(new_user.log, flag=1)
        self.usermod("usermod -g " + str(new_user.log) + " " + str(new_user.log), flag=1)
        self.connection.send(str(new_user.log + " was created successfully.\n").encode())

    def userdel(self, user_log):
        with open("passwords.txt", 'r') as f:
            logins = f.read().split()
            if self.user.log not in logins:
                self.connection.send("Error: login doesn't exist.\n".encode())
                return False
        if user_log == self.user.log:
            self.connection.send("Error: suicide is prohibited on the territory of the Russian Federation.\n".encode())
            return False
        with open("sessions.txt", 'r') as f:
            logins = f.read().split()
        if user_log in logins:
            self.connection.send("Error: cannot delete user while he is logged in\n".encode())
        else:
            try:    # delete directory
                shutil.rmtree(str("C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D"
                                  + "\\" + user_log), ignore_errors=True)
            except OSError:
                pass
            with open("passwords.txt", 'r+') as f:
                lines = f.readlines()
                lines = [lines[i] for i in range(len(lines)) if user_log not in lines[i]]
            line = "".join(lines[-1:]).replace("\n", "")
            lines = lines[:-1]
            lines.append(line)
            with open("passwords.txt", 'w') as f:
                f.writelines(lines)
            self.groupdel(user_log, flag=1)
            self.delete_rights(user_log)
            with open('groups.txt', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if user_log in line:
                        self.usermod("usermod -r " + str(line.split()[0][:-1]) + " " + str(user_log), flag=1)
            self.connection.send(str(user_log + " was deleted successfully.\n").encode())

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

    def userinfo(self, command_string):
        user_log = None
        if len(command_string.split()) > 1:
            user_log = command_string.split()[1]
        users_string = ''
        with open("passwords.txt", 'r') as f:
            lines = f.readlines()
        if user_log:
            for line in lines:
                if user_log in line.split():
                    users_string += str('*login: ' + line.split()[0] + '\n')
                    users_string += str('*password: ' + line.split()[1] + '\n')
                    users_string += str('*directory: ' + "D:\\" + line.split()[0] + '\n')
                    groups = self.check_groups(line.split()[0])
                    users_string += ('*groups: ' + ' '.join(groups) + '\n')
                    break
        else:
            for line in lines:
                if line != '\n':
                    users_string += str('*login: ' + line.split()[0] + '\n')
                    users_string += str('*password: ' + line.split()[1] + '\n')
                    users_string += str('*directory: ' + "D:\\" + line.split()[0] + '\n')
                    groups = self.check_groups(line.split()[0])
                    users_string += ('*groups: ' + ' '.join(groups) + '\n')
        self.connection.send(users_string.encode())

    def groupadd(self, group_name, flag=None):    # create group
        with open('groups.txt', 'r') as f:
            lines = f.readlines()
        with open('groups.txt', 'w') as f:
            for line in lines:
                f.writelines(line)
            f.writelines('\n' + str(group_name) + ':')
        if flag is None:
            self.connection.send(str.encode("Group list was updated.\n"))

    def usermod(self, command_string, flag=None):  # usermod -g/-r group_name user_name
        command_string = command_string.split()
        arg = command_string[1][1]
        group_name = command_string[2]
        user_name = command_string[3]
        with open('groups.txt', 'r') as f:
            lines = f.readlines()
        if group_name in "".join(lines).replace(":", ""):
            if arg == 'g':  # добавить пользователя в группу(-g)
                with open('groups.txt', 'w') as f:
                    for line in lines:
                        if line.split()[0][:-1] == group_name:
                            if line[-1:] == "\n":
                                line += ' ' + str(user_name)
                                line = line.replace("\n", "")
                                line += "\n"
                            else:
                                line += ' ' + str(user_name)
                        f.writelines(line.replace("  ", " "))
            else:    # удалить пользователя из группы(-r)
                with open('groups.txt', 'w') as f:
                    for line in lines:
                        if line.split()[0][:-1] == group_name:
                            line = line.split(":")[0] + ":" + str(line.replace(str(user_name), "").split(":")[1])
                        f.writelines(line.replace("  ", " "))
            if flag is None:
                self.connection.send(str.encode("Group list was updated.\n"))
        else:
            self.connection.send(str.encode("Group with this name doesn't exist.\n"))

    def groupdel(self, group_name, flag=None):
        with open('groups.txt', 'r') as f:
            lines = f.readlines()
        if "".join(lines[-1:]).split()[0] == str(group_name + ":"):
            string = str.strip("".join(lines[-2:][0]))
            lines = lines[:-2]
            lines.append(string)
        with open('groups.txt', 'w') as f:
            for line in lines:
                if line.split()[0][:-1] != group_name:
                    f.writelines(line)
        if flag is None:
            self.connection.send(str.encode("Group list was updated.\n"))


def multi_threaded_client(connection, user):
    print('Connected with', user[1])
    sr = Server(connection)
    sr.update_rights()
    if sr.auth():
        while True:
            try:
                print("wait for data")
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
                    if args < 3:
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
                elif command == 'rr':
                    if len(list(data.decode('utf-8').split())) == 1:
                        connection.send(str.encode("Error: missing file name.\n"))
                        continue
                    else:
                        sr.rr(data.decode('utf-8'))
                elif command == 'chmod':
                    if len(list(data.decode('utf-8').split())) < 5:
                        connection.send(str.encode("Error: missing file name.\n"))
                        continue
                    else:
                        sr.chmod(data.decode('utf-8'))
                elif 'adm' in sr.user.group:
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
                            continue
                        sr.passwd(data.decode('utf-8').split()[1])
                    elif command == 'userinfo':
                        sr.userinfo(data.decode('utf-8'))
                    elif command == 'groupadd':
                        if len(data.decode('utf-8').split()) != 2:
                            connection.send("Error: missing argument\n".encode())
                            continue
                        sr.groupadd(data.decode('utf-8').split()[1])
                    elif command == 'usermod':
                        if len(data.decode('utf-8').split()) != 4:
                            connection.send("Error: missing argument\n".encode())
                            continue
                        if data.decode('utf-8').split()[1][1] not in ['g', 'r']:
                            connection.send("Error: wrong argument\n".encode())
                            continue
                        sr.usermod(data.decode('utf-8'))
                    elif command == 'groupdel':
                        if len(data.decode('utf-8').split()) != 2:
                            connection.send("Error: missing argument\n".encode())
                            continue
                        sr.groupdel(data.decode('utf-8').split()[1])
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

    while True:
        Client, address = ServerSideSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(multi_threaded_client, (Client, address))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSideSocket.close()
