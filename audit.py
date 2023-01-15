import server as s


n = 30


class Audit:

    def __init__(self):
        self.objects_list = dict()
        self.subjects_list_g = dict()
        self.subjects_list_u = dict()
        self.journal = list()
        self.attr = dict()
        self.count = 0
        self.clear_journal()
        self.load_objects_list()
        self.load_subjects_list()

    def load_objects_list(self):
        with open('permissions.txt', 'r') as _:
            lines = _.readlines()
            for line in lines:
                line = line.replace('\n', '')
                line = line.split('|')
                if line[0] not in self.objects_list.keys():
                    self.objects_list[line[0]] = '111'    # read|write|append

    def load_subjects_list(self):
        with open('users_marks.txt', 'r') as _:
            users = _.readlines()
        with open('groups_marks.txt', 'r') as _:
            groups = _.readlines()
        for user in users:
            if user.split()[0] not in self.subjects_list_u.keys():
                self.subjects_list_u[user.split()[0]] = '11'  # read|write
        for group in groups:
            if group.split()[0] not in self.subjects_list_g.keys():
                self.subjects_list_g[group.split()[0]] = '11'  # read|write

    def append_journal(self, mode, user_name, file_name):
        self.check_attributes(mode, subject_name=user_name, object_name=file_name, object_=1)
        self.check_attributes(mode, subject_name=user_name, object_name=file_name, subject=1)
        self.check_attribute_g(mode, user_name, file_name)

    def check_attributes(self, mode, subject_name, object_name, subject=None, object_=None):
        if object_ is not None:
            attr = self.objects_list.get(object_name)
            if mode == 'r' and int(attr[0]) == 1:
                self.append(str('File ' + object_name + ' was read by ' + subject_name))
                print(str('File ' + object_name + ' was read by ' + subject_name))
            if mode == 'w' and int(attr[1]) == 1:
                self.append(str('File ' + object_name + ' was written by ' + subject_name))
                print(str('File ' + object_name + ' was written by ' + subject_name))
            if mode == 'a' and int(attr[2]) == 1:
                return True
        elif subject is not None:
            attr = self.subjects_list_u.get(subject_name)
            if mode == 'r' and int(attr[0]) == 1:
                self.append(str(subject_name + ': read file ' + object_name))
                print(str(subject_name + ': read file ' + object_name))
            if mode == 'w' and int(attr[1]) == 1:
                self.append(str(subject_name + ': wrote in file ' + object_name))
                print(str(subject_name + ': wrote in file ' + object_name))
        return False

    def check_attribute_g(self, mode, user_name, file_name):
        groups = s.Server.check_groups(user_name)
        for group in groups:
            attr = self.subjects_list_g.get(group)
            if mode == 'r' and int(attr[0]) == 1:
                self.append(str('Member of group ' + group + ' read file ' + file_name))
                print(str('Member of group ' + group + ' read file ' + file_name))
            if mode == 'w' and int(attr[1]) == 1:
                self.append(str('Member of group ' + group + ' wrote in file ' + file_name))
                print(str('Member of group ' + group + ' read file ' + file_name))

    def append(self, action_string):
        with open("sessions.txt", 'r') as _:
            logins = _.read().split()
            if 'doom' in logins:
                self.journal.append(action_string)
                self.count += 1
                if self.count == n:
                    self.save_journal()
                    self.count = 0

    def save_journal(self):
        with open("journal.txt", "w") as _:
            count = 0
            for line in self.journal:
                count += 1
                if count == len(self.journal):
                    _.writelines(str(line))
                else:
                    _.writelines(str(line) + "\n")
        self.journal.pop(0)

    def clear_journal(self):
        self.journal.clear()
        with open("journal.txt", "wb") as _:
            pass
