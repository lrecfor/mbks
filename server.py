import socket
from _thread import *
import os
import shutil
import hashlib
from datetime import datetime
import re
import users as u
import objects as f
import groups as g
import audit as a

count_users = 0
clr_sessions = False


class Server:

    def __init__(self, connect, audit_ptr):
        self.connection = connect
        self.user = u.User()
        self.access_list = f.Objects()
        self.group_list = g.Groups()
        self.users_marks = dict()
        self.audit = audit_ptr

    def check_login(self):
        with open("passwords.txt", 'r') as _:
            logins = _.read().split()
            if self.user.log in logins:
                return True
        self.connection.send("Error: login doesn't exist.\nLogin: ".encode())
        return False

    def check_session(self):
        with open("sessions.txt", 'r') as _:
            logins = _.read().split()
            if self.user.log not in logins:
                return True
        self.connection.send("Error: you already logged in.\nLogin: ".encode())
        return False

    def check_password(self):
        with open("passwords.txt", 'r') as _:
            passwd_hash = hashlib.sha256(self.user.passwd.encode())
            passwd = passwd_hash.hexdigest()
            for line in _:
                if len(line) > 1:
                    if self.user.log == line.split()[0] and passwd == line.split()[1]:
                        return True
        self.connection.send("Error: password is incorrect.\nPassword: ".encode())
        return False

    def check_mark(self, mark):
        with open("users_marks.txt", 'r') as _:
            marks = _.readlines()
            marks_d = dict()
            for i in range(len(marks)):
                marks_d[marks[i].split()[0]] = marks[i].split()[1]
            if mark <= marks_d.get(self.user.log) and int(mark) > 0:
                return True
        self.connection.send("Error: incorrect mark.\nMark: ".encode())
        return False

    @staticmethod
    def check_groups(login):
        with open('groups.txt', 'r') as _:
            lines = _.readlines()
        groups = []
        for line in lines:
            if login in line.split():
                groups.append(line.split()[0][:-1])
        return groups

    def load_groups(self):
        self.group_list.groups.clear()
        with open("groups_marks.txt", "r") as __:
            marks = __.readlines()
            marks_d = dict()
            for i in range(len(marks)):
                marks_d[marks[i].split()[0]] = marks[i].split()[1]

        with open('groups.txt', 'r') as _:
            lines = _.readlines()
            for line in lines:
                line = line.replace('\n', '')
                line = line.split(':')
                self.group_list.append_group(line[0], list(line[1].split()), marks_d.get(line[0]))

    def save_groups(self):
        count = 0
        with open('groups.txt', 'w') as _:
            for group in self.group_list.groups:
                count += 1
                if count != len(self.group_list.groups):
                    _.writelines(str(group.name + ": " + " ".join(group.participants) + "\n"))
                else:
                    _.writelines(str(group.name + ": " + " ".join(group.participants)))
        count = 0
        with open("groups_marks.txt", "w") as __:
            for group in self.group_list.groups:
                count += 1
                if count != len(self.group_list.groups):
                    __.writelines(str(group.name + " " + str(group.mark) + "\n"))
                else:
                    __.writelines(str(group.name + " " + str(group.mark)))

    def auth(self):
        global count_users
        done = False
        log_checked = False
        passwd_checked = False
        mark_checked = False
        attempt_p = 0
        while not done:
            try:
                self.connection.send("Login: ".encode())
                while not log_checked:
                    self.user.log = self.connection.recv(1024).decode()
                    if not self.check_login():
                        continue
                    if not self.check_session():
                        self.audit.append(str('Unsuccessful attempt to login to the account ' + self.user.log))
                        print(str('Unsuccessful attempt to login to the account ' + self.user.log))
                        continue
                    log_checked = True

                self.connection.send("Password: ".encode())
                while not passwd_checked:
                    self.user.passwd = self.connection.recv(1024).decode()
                    if not self.check_password():
                        attempt_p += 1
                        continue
                    passwd_checked = True

                self.connection.send("Mark: ".encode())
                while not mark_checked:
                    mark = self.connection.recv(1024).decode()
                    if not self.check_mark(mark):
                        continue
                    self.user.mark = int(mark)
                    mark_checked = True

                with open("sessions.txt", 'a') as _:
                    _.write(self.user.log + '\n')
                    self.connection.send(str(self.user.log + ' logged in successfully.\n').encode())
                    count_users += 1
                    done = True

            except WindowsError:
                self.logout('unexpected')
                return False
        if self.user.log != 'doom':
            self.audit.append(str(self.user.log + ' logged in successfully at ' + datetime.now().strftime("%H:%M:%S") + ' IP: 127.0.0.1 ' +
                                  'Unsuccessful attempts: ' + str(attempt_p)))
            print(str(self.user.log + ' logged in successfully at ' + datetime.now().strftime("%H:%M:%S") + ' IP: 127.0.0.1 ' +
                      'Unsuccessful attempts: ' + str(attempt_p)))
        self.create_directory()
        return True

    def create_directory(self):
        path = os.getcwd() + "\\D\\" + self.user.log + "\\home"
        self.user.path = os.getcwd() + "\\D\\" + self.user.log
        self.user.dir = os.getcwd() + "\\D\\" + self.user.log + "\\home"
        try:
            os.makedirs(path)
        except OSError:
            pass

    def del_directory(self):
        try:
            shutil.rmtree(self.user.path, ignore_errors=True)
        except TypeError:
            pass

    def add_rights(self, subject_name, object_name, permissions, mark=0):
        self.access_list.append_object(object_name, subject_name, str(permissions), mark)
        self.save_rights()

    def change_rights(self, subject_type, object_name, permission):
        self.load_rights()
        for obj in self.access_list.objects:
            if obj.name == object_name:
                if subject_type == "u":
                    obj.owner_p = permission
                elif subject_type == "g":
                    obj.group_p = permission
                else:
                    obj.others_p = permission
                break
        self.save_rights()

    def get_rights(self, object_name):
        self.load_rights()
        for obj in self.access_list.objects:
            if obj.name == object_name:
                string = list(vars(obj).values())
                name = "".join(list(string[0].split("\\"))[-1:])
                string = string[2] + string[3] + string[4] + "\t" + string[1] + "\t" + name + "\t" + obj.mark
                return str(string + "\n")
        return False

    @staticmethod
    def delete_marks(user_name):
        with open("users_marks.txt", 'r') as _:
            lines = _.readlines()
        count = 0
        with open("users_marks.txt", 'w') as _:
            for line in lines:
                line = line.replace("\n", "")
                if line.split()[0] != user_name:
                    count += 1
                    if count != len(lines) - 1:
                        _.writelines(line + "\n")
                    else:
                        _.writelines(line)

    def load_users_marks(self):
        with open("users_marks.txt", "r") as _:
            lines = _.readlines()
        for line in lines:
            self.users_marks[line.split()[0]] = line.split()[1]

    def save_users_marks(self):
        with open("users_marks.txt", "w") as _:
            count = 0
            for i in self.users_marks:
                count += 1
                if count == len(self.users_marks):
                    _.writelines(str(i + " " + self.users_marks[i]))
                else:
                    _.writelines(str(i + " " + self.users_marks[i] + "\n"))

    def change_marks(self, obj_type, object_name, new_mark):      # chm u|g|o object_name new_mark
        if obj_type == "u":
            self.load_users_marks()
            self.users_marks[object_name] = new_mark
            self.save_users_marks()
        elif obj_type == "g":
            self.load_groups()
            for group in self.group_list.groups:
                if group.name == object_name:
                    group.mark = new_mark
                    break
            self.save_groups()
        elif obj_type == "o":
            self.load_rights()
            for obj in self.access_list.objects:
                if obj.name == object_name:
                    obj.mark = new_mark
                    break
            self.save_rights()

    def check_rights_dac(self, subject_name, object_name, right_type):  # 2 - write, 4 - read, 6 - write+read
        if right_type == 1:
            right_type = 2
        self.load_rights()
        ret = list()
        for obj in self.access_list.objects:
            if obj.name == object_name:
                if obj.owner == subject_name:
                    if int(obj.group_p) == right_type or int(obj.group_p) == 6:
                        ret.append(True)
                    else:
                        ret.append(False)
                else:
                    if obj.owner in self.check_groups(subject_name):
                        if int(obj.group_p) == right_type or int(obj.group_p) == 6:
                            ret.append(True)
                        else:
                            ret.append(False)
                    if int(obj.others_p) == right_type or int(obj.others_p) == 6:
                        ret.append(True)
                    else:
                        ret.append(False)
                if False in ret:
                    return False
                return True

    def check_rights_mac(self, subject_name, object_name, right_type):
        self.load_groups()
        self.load_users_marks()
        self.load_rights()
        ret = list()
        for obj in self.access_list.objects:
            if obj.name == object_name:
                if obj.owner == subject_name:
                    if int(obj.mark) == self.user.mark and right_type == 2 or \
                            self.user.mark >= int(obj.mark) and right_type == 4 or \
                            self.user.mark <= int(obj.mark) and right_type == 1:
                        ret.append(True)
                    else:
                        ret.append(False)
                else:
                    mark = None
                    if obj.owner in self.check_groups(subject_name):
                        for group in self.group_list.groups:
                            if group.name == obj.owner:
                                mark = int(group.mark)
                                break
                        if int(obj.mark) == mark and right_type == 2 or \
                                mark >= int(obj.mark) and right_type == 4 or \
                                mark <= int(obj.mark) and right_type == 1:
                            ret.append(True)
                        else:
                            ret.append(False)
                    if int(obj.mark) == self.user.mark and right_type == 2 or \
                            self.user.mark >= int(obj.mark) and right_type == 4 or \
                            self.user.mark <= int(obj.mark) and right_type == 1:
                        ret.append(True)
                    else:
                        ret.append(False)
                if False in ret:
                    return False
                return True

    def check_rights(self, subject_name, object_name, right_type):
        if not self.check_rights_dac(subject_name, object_name, right_type):
            if self.user.log != "doom":
                self.connection.send(str.encode('DAC: access denied.\n'))
                self.audit.append(str(subject_name + ': trying to access ' + object_name + '. DAC: access denied.'))
                print(str(subject_name + ': trying to access ' + object_name + '. DAC: access denied.'))
            return
        else:
            if self.user.log != "doom":
                self.audit.append(str(subject_name + ': trying to access ' + object_name + '. DAC: access is allowed.'))
                print(str(subject_name + ': trying to access ' + object_name + '. DAC: access is allowed.'))

        if not self.check_rights_mac(subject_name, object_name, right_type):
            self.connection.send(str.encode('MAC: access denied.\n'))
            if self.user.log != "doom":
                self.audit.append(str(subject_name + ': trying to access ' + object_name + '. MAC: access denied.'))
                print(str(subject_name + ': trying to access ' + object_name + '. MAC: access denied.'))
            return
        else:
            if self.user.log != "doom":
                self.audit.append(str(subject_name + ': trying to access ' + object_name + '. MAC: access is allowed.'))
                print(str(subject_name + ': trying to access ' + object_name + '. MAC: access is allowed.'))
        return True

    def load_rights(self):
        self.access_list.objects.clear()
        with open('permissions.txt', 'r') as _:
            lines = _.readlines()
            for line in lines:
                line = line.replace('\n', '')
                line = line.split('|')
                self.access_list.append_object(line[0], line[1],
                                               str(line[2] + line[3] + line[4]), str(line[5]))

    def delete_rights(self, object_name=None, subject_name=None):
        delete = list()
        if subject_name:
            for obj in self.access_list.objects:
                if obj.owner == subject_name:
                    delete.append(obj)
            for obj in delete:
                self.access_list.objects.remove(obj)
        elif object_name:
            for obj in self.access_list.objects:
                if obj.name == object_name:
                    self.access_list.objects.remove(obj)
                    break
        self.save_rights()

    def save_rights(self):
        with open('permissions.txt', 'w') as _:
            count = 0
            for obj in self.access_list.objects:
                count += 1
                if count == len(self.access_list.objects):
                    _.write('|'.join(list(vars(obj).values())))
                else:
                    _.write(str('|'.join(list(vars(obj).values())) + "\n"))

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
            elif command_name == "rm":
                self.connection.send("Usage: rm [filename]\nDelete the file.\n".encode())
            elif command_name == "rr":
                self.connection.send("Usage: rr [objectName]\nPrint the permissions for the object_.\n".encode())
            elif command_name == "chmod":
                self.connection.send("Usage: chmod [objectName] [u|g|o] [permission]\n"
                                     "Change permission for OBJECT.\n".encode())
            elif command_name == "cm":
                self.connection.send("Usage: cm [u|o] [objectName]\n. Display mark of OBJECT.\n".encode())
            elif command_name == "touch":
                self.connection.send("Usage: touch [filename] [permission] [mark].\n"
                                     "Create new file.\n".encode())
            elif command_name == "chm":
                self.connection.send("Usage: chm [u|g|o] [object_name] [new_mark].\n Change OBJECT mark.\n".encode())
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
            with open("sessions.txt", "r") as _:
                file = list(_)
            with open("sessions.txt", "w") as _:
                if str(self.user.log + '\n') in file:
                    file.remove(self.user.log + '\n')
                for line in file:
                    _.write(line)
        if unexpected is not None:
            try:
                self.audit.append(str('Lost connection with ' + self.user.log + ' at ' +
                                      datetime.now().strftime("%H:%M:%S")))
                print('Lost connection with', self.user.log + '.')
            except TypeError:
                pass
        else:
            self.audit.append(str(self.user.log + ' logged out successfully at ' + datetime.now().strftime("%H:%M:%S")))
            print(self.user.log + ' logged out successfully at ' + datetime.now().strftime("%H:%M:%S"))
            self.connection.send(str('You successfully logged out\n'
                                     'Dou you wanna continue with another account? (y/n)\n').encode())
            data = self.connection.recv(2048)
            if data.decode('utf-8')[0] == 'y':
                self.auth()
            else:
                self.connection.send(str("Stop").encode())

    # check_rights
    # audit
    def ls(self, command_string):
        if len(list(command_string.split())) == 1:
            dir_name = self.user.dir
        else:
            dir_name = command_string.split()[1]
            if "/" in dir_name:
                dir_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(dir_name.split("/")[1:])
            else:
                dir_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(dir_name.split("\\")[1:])
            print(dir_name)

        if not self.group_list.find("adm", self.user.log):
            if not self.check_rights(self.user.log, dir_name, 4):
                return False

        files = os.listdir(dir_name)
        files_list = ''
        for file in files:
            files_list += file + ' '
        files_list += '\n'
        if len(files_list) == 0:
            files_list = '(empty)\n'
        self.connection.send(str.encode(files_list))

    # check_rights
    # audit
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

            if not os.path.isfile(file_name):
                self.add_rights(self.user.log, file_name, str(666))
                self.audit.load_objects_list()
            else:
                if not self.group_list.find("adm", self.user.log):
                    '''dir_name = "\\".join(file_name.split("\\")[:-1])
                    if not self.check_rights(self.user.log, dir_name, 2):
                        return False'''

                    if not self.check_rights(self.user.log, file_name, 2):
                        return False
            with open(file_name, "w") as _:
                _.write(text)

            self.audit.append_journal('w', self.user.log, file_name)
            self.connection.send(str.encode('File was written successfully.\n'))
        return True

    # check_rights
    # audit
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

        if not self.group_list.find("adm", self.user.log):
            '''dir_name = "\\".join(file_name.split("\\")[:-1])
            if not self.check_rights(self.user.log, dir_name, 4):
                return False'''

            if not self.check_rights(self.user.log, file_name, 4):
                return False

        try:
            with open(file_name, 'r', encoding='utf-8') as _:
                try:
                    text = _.read()
                except UnicodeDecodeError:
                    self.connection.send(str.encode('UnicodeDecodeError: utf-8 codec can\'t decode.\n'))
                    return False
        except IOError:
            self.connection.send(str.encode('Error: incorrect file name.\n'))
            return False
        self.connection.send(str.encode(str(len(text))))
        self.connection.send(str(text).encode('utf-8'))
        self.audit.append_journal('r', self.user.log, file_name)

    def rm(self, command_string):
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
        try:
            os.remove(file_name)
        except OSError:
            self.connection.send(str.encode("Error: something went wrong.\n"))
        self.delete_rights(file_name)
        self.connection.send(str.encode("File was deleted successfully.\n"))

    def rr(self, command_string):   # check rights for object_
        command_string = command_string.split()
        object_name = command_string[1]
        if object_name[1] != ':':
            object_name = self.user.dir + '\\' + object_name
        else:
            if "/" in object_name:
                object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(object_name.split("/")[1:])
            else:
                object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                            + "\\".join(object_name.split("\\")[1:])
        rights = self.get_rights(object_name)
        if rights:
            rights = "".join(list(rights))
            self.connection.send(str.encode(rights))
        else:
            self.connection.send(str.encode("Error: no such object_.\n"))

    def chmod(self, command_string):    # chmod object_name u|g|o permission
        command_string = command_string.split()
        object_name = command_string[1]
        try:
            if object_name[1] != ':':
                object_name = self.user.dir + '\\' + object_name
            else:
                if "/" in object_name:
                    object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                + "\\".join(object_name.split("/")[1:])
                else:
                    object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                + "\\".join(object_name.split("\\")[1:])
        except IndexError:
            self.connection.send(str.encode("Error: something went wrong.\n"))
            return False

        subject_type = command_string[2]
        permission = command_string[3]

        if subject_type == "u":
            self.change_rights(subject_type, object_name, permission)
        elif subject_type == "g":
            self.change_rights(subject_type, object_name, permission)
        elif subject_type == "o":
            self.change_rights(subject_type, object_name, permission)
        self.connection.send(str.encode("Permissions were updated.\n"))

    # audit
    def append(self, command_string):
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

            if not self.group_list.find("adm", self.user.log):
                '''dir_name = "\\".join(file_name.split("\\")[:-1])
                if not self.check_rights(self.user.log, dir_name, 1):
                    return False'''

                if not self.check_rights(self.user.log, file_name, 1):
                    return False

            if not os.path.isfile(file_name):
                self.connection.send(str.encode('Error: file is not exist.\n'))
                return False
            with open(file_name, "a") as _:
                _.write(text)
            self.audit.append_journal('a', self.user.log, file_name)
            self.connection.send(str.encode('File was written successfully.\n'))
        return True

    def cm(self, command_string):   # cm -u|-g|-o name
        command_string = command_string.split()
        if command_string[1] == '-u':
            if self.user.log == command_string[2]:
                self.connection.send(str.encode(str(command_string[2] + "\t"
                                                    + str(self.user.mark) + "\n")))
            else:
                self.connection.send(str.encode(str(command_string[2] + "\t"
                                                + str(self.users_marks[command_string[2]]) + "\n")))
        elif command_string[1] == '-o':
            file_name = command_string[2]
            if file_name[1] != ':':
                file_name = self.user.dir + '\\' + file_name
            else:
                if "/" in file_name:
                    file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                + "\\".join(file_name.split("/")[1:])
                else:
                    file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                + "\\".join(file_name.split("\\")[1:])
            for obj in self.access_list.objects:
                if obj.name == file_name:
                    self.connection.send(str.encode(str(command_string[2] + "\t" + str(obj.mark) + "\n")))
                    break
        elif command_string[1] == '-g':
            self.load_groups()
            for group in self.group_list.groups:
                if group.name == command_string[2]:
                    self.connection.send(str.encode(str(command_string[2] + "\t" + str(group.mark) + "\n")))
                    break
        else:
            self.connection.send(str.encode("Error: wrong argument.\n"))
            return False

    def touch(self, command_string):
        command_string = command_string.split()
        file_name = command_string[1]
        permissions = str(command_string[2])
        mark = command_string[3]
        if len(file_name) < 5 or file_name[-4:] != ".txt":
            self.connection.send('Error: wrong file name.\n'.encode())
            return False
        if not re.match("^[0246]+$", permissions):
            self.connection.send('Error: wrong permissions.\n'.encode())
            return False
        if file_name[1] != ':':
            file_name = self.user.dir + '\\' + file_name
        else:
            if "/" in file_name:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                              + "\\".join(file_name.split("/")[1:])
            else:
                file_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                              + "\\".join(file_name.split("\\")[1:])
        if os.path.isfile(file_name):
            self.connection.send(str.encode("File is already exist.\n"))
            return False
        try:
            with open(file_name, "w"):
                pass
        except OSError:
            self.connection.send(str.encode("Error: something went wrong.\n"))
        self.add_rights(self.user.log, file_name, permissions, mark)
        self.audit.load_objects_list()
        self.connection.send(str.encode("File was created successfully.\n"))

    def chm(self, command_string):  # chm u|g|o object_name new_mark
        self.load_users_marks()
        self.load_groups()
        self.load_rights()
        command_string = command_string.split()
        arg = command_string[1]
        object_name = command_string[2]
        if arg == "o":
            if object_name[1] != ':':
                object_name = self.user.dir + '\\' + object_name
            else:
                if "/" in object_name:
                    object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                  + "\\".join(object_name.split("/")[1:])
                else:
                    object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                  + "\\".join(object_name.split("\\")[1:])
        new_mark = command_string[3]
        if arg == "u":
            if object_name not in self.users_marks.keys():
                self.connection.send(str.encode("Error: wrong object_ name.\n"))
                return False
        elif arg == "g":
            g_list = list()
            for group in self.group_list.groups:
                g_list.append(group.name)
            if object_name not in g_list:
                self.connection.send(str.encode("Error: wrong object_ name.\n"))
                return False
        elif arg == "o":
            obj_list = list()
            for obj in self.access_list.objects:
                obj_list.append(obj.name)
            if object_name not in obj_list:
                self.connection.send(str.encode("Error: wrong object_ name.\n"))
                return False
        else:
            self.connection.send(str.encode("Error: wrong argument.\n"))
            return False
        self.change_marks(arg, object_name, new_mark)
        self.connection.send(str.encode("Mark was successfully changed.\n"))

    # admins functions
    def useradd(self):
        new_user = u.User()
        self.connection.send("New login: ".encode())
        new_user.log = self.connection.recv(1024).decode()
        with open("passwords.txt", 'r') as _:
            logins = _.read()
            if new_user.log in logins.split():
                self.connection.send("Error: user is already exist.\n".encode())
                return False
        self.connection.send("New password: ".encode())
        new_user.passwd = self.connection.recv(1024).decode()
        with open("passwords.txt", 'a') as _:
            hashed_passwd = hashlib.sha256(new_user.passwd.encode('utf-8')).hexdigest()
            _.write(str('\n' + new_user.log + ' ' + hashed_passwd))
        self.connection.send("New mark: ".encode())
        new_user.mark = self.connection.recv(1024).decode()
        with open("users_marks.txt", 'a') as _:
            _.writelines(str("\n" + str(new_user.log) + " " + str(new_user.mark)))
        # create directory
        try:
            path = os.getcwd() + "\\D\\" + new_user.log + "\\home"
            new_user.path = os.getcwd() + "\\D\\" + new_user.log
            new_user.dir = os.getcwd() + "\\D\\" + new_user.log + "\\home"
            os.makedirs(path)
        except OSError:
            self.connection.send("Error: something went wrong.\n".encode())
            return False

        # create permissions for home dir
        self.add_rights(new_user.log, path, str(666))    # full access only for owner and read for others subjects
        self.add_rights(new_user.log, str(os.getcwd() + "\\D\\" + new_user.log), str(666), 4)

        self.groupadd(new_user.log, flag=1)
        self.usermod("usermod -g " + str(new_user.log) + " " + str(new_user.log), flag=1)
        self.audit.load_subjects_list()
        self.connection.send(str(new_user.log + " was created successfully.\n").encode())

    def userdel(self, user_log):
        with open("passwords.txt", 'r') as _:
            logins = _.read().split()
            if self.user.log not in logins:
                self.connection.send("Error: login doesn't exist.\n".encode())
                return False
        if user_log == self.user.log:
            self.connection.send("Error: suicide is prohibited on the territory of the Russian Federation.\n".encode())
            return False
        with open("sessions.txt", 'r') as _:
            logins = _.read().split()
        if user_log in logins:
            self.connection.send("Error: cannot delete user while he is logged in\n".encode())
        else:
            try:    # delete directory
                shutil.rmtree(str("C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D"
                                  + "\\" + user_log), ignore_errors=True)
            except OSError:
                pass
            with open("passwords.txt", 'r+') as _:
                lines = _.readlines()
                lines = [lines[i] for i in range(len(lines)) if user_log not in lines[i]]
            line = "".join(lines[-1:]).replace("\n", "")
            lines = lines[:-1]
            lines.append(line)
            with open("passwords.txt", 'w') as _:
                _.writelines(lines)
            self.delete_marks(user_log)
            self.groupdel(user_log, flag=1)
            for group in self.group_list.groups:
                if user_log in group.participants:
                    group.participants.remove(user_log)
            self.group_list.delete_group(user_log)
            self.save_groups()
            self.delete_rights(subject_name=user_log)
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
        with open("passwords.txt", 'r+') as _:
            lines = _.readlines()
        with open("passwords.txt", 'w') as _:
            for line in lines:
                if user_log in line:
                    line = str(user_log + ' ' + hashed_new_passwd + '\n')
                _.writelines(line)
        self.connection.send("passwd: password updated successfully\n".encode())

    def userinfo(self, command_string):
        user_log = None
        if len(command_string.split()) > 1:
            user_log = command_string.split()[1]
        users_string = ''
        with open("passwords.txt", 'r') as _:
            lines = _.readlines()
        with open("users_marks.txt", "r") as __:
            marks = __.readlines()
            marks_d = dict()
            for i in range(len(marks)):
                marks_d[marks[i].split()[0]] = marks[i].split()[1]
        if user_log:
            for line in lines:
                if user_log in line.split():
                    users_string += str('*login: ' + line.split()[0] + '\n')
                    users_string += str('*password: ' + line.split()[1] + '\n')
                    users_string += str('*directory: ' + "D:\\" + line.split()[0] + '\n')
                    groups = self.check_groups(line.split()[0])
                    users_string += ('*groups: ' + ' '.join(groups) + '\n')
                    users_string += str('*mark: ' + marks_d.get(line.split()[0]) + "\n")
                    break
        else:
            for line in lines:
                if line != '\n':
                    users_string += str('*login: ' + line.split()[0] + '\n')
                    users_string += str('*password: ' + line.split()[1] + '\n')
                    users_string += str('*directory: ' + "D:\\" + line.split()[0] + '\n')
                    groups = self.check_groups(line.split()[0])
                    users_string += ('*groups: ' + ' '.join(groups) + '\n')
                    users_string += str('*mark: ' + marks_d.get(line.split()[0]) + "\n")
        self.connection.send(users_string.encode())

    def groupadd(self, group_name, flag=None, mark=0):    # create group
        for group in self.group_list.groups:
            if group.name == group_name:
                self.connection.send(str.encode("Error: this group already exists.\n"))
                return False
        self.group_list.append_group(group_name, list(), mark)
        self.save_groups()
        self.audit.load_subjects_list()
        if flag is None:
            self.connection.send(str.encode("Group list was updated.\n"))

    def usermod(self, command_string, flag=None):  # usermod -g/-r group_name user_name
        command_string = command_string.split()
        arg = command_string[1][1]
        group_name = command_string[2]
        user_name = command_string[3]
        with open('groups.txt', 'r') as _:
            lines = _.readlines()
        if group_name in "".join(lines).replace(":", ""):
            if arg == 'g':  # добавить пользователя в группу(-g)
                for group in self.group_list.groups:
                    if group.name == group_name:
                        group.participants.append(user_name)
            else:    # удалить пользователя из группы(-r)
                for group in self.group_list.groups:
                    if group.name == group_name:
                        try:
                            group.participants.remove(user_name)
                        except ValueError:
                            pass
            self.save_groups()
            if flag is None:
                self.connection.send(str.encode("Group list was updated.\n"))
        else:
            self.connection.send(str.encode("Group with this name doesn't exist.\n"))

    def groupdel(self, group_name, flag=None):
        flag_g = False
        for group in self.group_list.groups:
            if group.name == group_name:
                flag_g = True
        if not flag_g:
            self.connection.send(str.encode("Error: this group is not exist.\n"))
            return False
        self.group_list.delete_group(group_name)
        self.save_groups()
        if flag is None:
            self.connection.send(str.encode("Group list was updated.\n"))

    def display_attribute(self, command_string):    # dattr -u|-g|-o name
        command_string = command_string.split()
        arg_ = command_string[1]
        if arg_ == '-o':
            object_name = command_string[2]
            if len(object_name) < 5:
                self.connection.send('Error: wrong file name.\n'.encode())
                return False
            if object_name[1] != ':':
                object_name = self.user.dir + '\\' + object_name
            else:
                if "/" in object_name:
                    object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                  + "\\".join(object_name.split("/")[1:])
                else:
                    object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                                  + "\\".join(object_name.split("\\")[1:])
            attr = self.audit.objects_list.get(object_name)
            if attr is None:
                self.connection.send(str('Error: file does not exist.\n').encode())
                return False
        elif arg_ == '-u':
            subject_name = command_string[2]
            attr = self.audit.subjects_list_u.get(subject_name)
            if attr is None:
                self.connection.send(str('Error: subject does not exist.\n').encode())
                return False
        elif arg_ == '-g':
            subject_name = command_string[2]
            attr = self.audit.subjects_list_g.get(subject_name)
            if attr is None:
                self.connection.send(str('Error: subject does not exist.\n').encode())
                return False
        else:
            self.connection.send(str('Error: wrong argument.\n').encode())
            return False
        self.connection.send(str(attr + '\n').encode())

    def set_attribute(self, command_string):    # sattr name attr
        command_string = command_string.split()
        object_name = command_string[1]
        attr = str(command_string[2])
        if len(attr) != 3 or not re.match("^[01]+$", attr):
            self.connection.send('Error: wrong attribute.\n'.encode())
            return False
        if len(object_name) < 5:
            self.connection.send('Error: wrong file name.\n'.encode())
            return False
        if object_name[1] != ':':
            object_name = self.user.dir + '\\' + object_name
        else:
            if "/" in object_name:
                object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                              + "\\".join(object_name.split("/")[1:])
            else:
                object_name = "C:\\Users\\Дана Иманкулова\\projects\\python\\mbks\\D\\" \
                              + "\\".join(object_name.split("\\")[1:])

        if self.audit.objects_list.get(object_name) is None:
            self.connection.send('Error: file does not exist.\n'.encode())
            return False
        self.audit.objects_list[object_name] = attr
        self.connection.send('Attributes was changed successfully.\n'.encode())

    def set_audit(self, command_string):    # saudit -u|-g name attr
        command_string = command_string.split()
        arg_ = command_string[1]
        subject_name = command_string[2]
        attr = str(command_string[3])
        if len(attr) != 2 or not re.match("^[01]+$", attr):
            self.connection.send('Error: wrong attribute.\n'.encode())
            return False
        if arg_ == '-u':
            if self.audit.subjects_list_u.get(subject_name) is None:
                self.connection.send('Error: subject does not exist.\n'.encode())
                return False
            else:
                self.audit.subjects_list_u[subject_name] = attr
        elif arg_ == '-g':
            if self.audit.subjects_list_g.get(subject_name) is None:
                self.connection.send('Error: subject does not exist.\n'.encode())
                return False
            else:
                self.audit.subjects_list_g[subject_name] = attr
        else:
            self.connection.send('Error: wrong argument.'.encode())
            return False
        self.connection.send('Audit was set successfully.\n'.encode())

    def display_journal(self):
        string = ''
        if len(self.audit.journal) == 0:
            self.connection.send('Journal is empty.\n'.encode())
            return
        for note in self.audit.journal:
            string += str(note + '\n')
        self.connection.send(str(string).encode())


def multi_threaded_client(connection, user, audit):
    print('Connected with', user[1])
    sr = Server(connection, audit)
    sr.load_rights()
    sr.load_groups()
    sr.load_users_marks()
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
                if sr.group_list.find("audit", sr.user.log):
                    if command == 'sattr':
                        args = len(list(data.decode('utf-8').split()))
                        if args != 3:
                            connection.send(str.encode("Error: missing argument.\n"))
                            continue
                        if not sr.set_attribute(data.decode('utf-8')):
                            continue
                    elif command == 'dattr':
                        args = len(list(data.decode('utf-8').split()))
                        if args != 3:
                            connection.send(str.encode("Error: missing argument.\n"))
                            continue
                        if not sr.display_attribute(data.decode('utf-8')):
                            continue
                    elif command == 'saudit':
                        args = len(list(data.decode('utf-8').split()))
                        if args != 4:
                            connection.send(str.encode("Error: missing argument.\n"))
                            continue
                        if not sr.set_audit(data.decode('utf-8')):
                            continue
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
                elif command == 'rm':
                    if len(list(data.decode('utf-8').split())) == 1:
                        connection.send(str.encode("Error: missing file name.\n"))
                        continue
                    else:
                        sr.rm(data.decode('utf-8'))
                elif command == 'chmod':
                    if len(list(data.decode('utf-8').split())) < 4:
                        connection.send(str.encode("Error: missing argument.\n"))
                        continue
                    else:
                        if not sr.chmod(data.decode('utf-8')):
                            continue
                elif command == 'append':
                    args = len(list(data.decode('utf-8').split()))
                    if args < 3:
                        connection.send(str.encode("Error: missing argument.\n"))
                        continue
                    else:
                        if not sr.append(data.decode('utf-8')):
                            continue
                elif command == 'cm':
                    if len(list(data.decode('utf-8').split())) < 3:
                        connection.send(str.encode("Error: missing argument.\n"))
                        continue
                    else:
                        if not sr.cm(data.decode('utf-8')):
                            continue
                elif command == 'touch':
                    args = len(list(data.decode('utf-8').split()))
                    if args < 4:
                        connection.send(str.encode("Error: missing argument.\n"))
                        continue
                    else:
                        if not sr.touch(data.decode('utf-8')):
                            continue
                elif command == 'chm':
                    args = len(list(data.decode('utf-8').split()))
                    if args < 4:
                        connection.send(str.encode("Error: missing argument.\n"))
                        continue
                    else:
                        if not sr.chm(data.decode('utf-8')):
                            continue
                elif command == 'cat':
                    sr.display_journal()
                elif sr.group_list.find("adm", sr.user.log):
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
                        if len(data.decode('utf-8').split()) < 2:
                            connection.send("Error: missing argument\n".encode())
                            continue
                        if not sr.groupadd(data.decode('utf-8').split()[1], mark=data.decode('utf-8').split()[2]):
                            continue
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

    audit_ = a.Audit()

    while True:
        Client, address = ServerSideSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(multi_threaded_client, (Client, address, audit_))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
