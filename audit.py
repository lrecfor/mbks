import server as s


n = 10


class Audit:

    def __init__(self):
        # специальные атрибуты аудита у каждого объекта (например, аудит чтения, аудит записи, аудит дозаписи)
        self.objects_list = dict()
        self.subjects_list_g = dict()
        self.subjects_list_u = dict()
        self.journal = list()
        self.attr = dict()
        self.count = 0
        self.clear_journal()
        self.load_objects_list()
        self.load_subjects_list()

    def load_subjects_list(self):
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

    def check_attribute(self, mode, object_name=None, subject_name=None, subject_type=None):
        if mode == 'auth':
            return True
        if object_name is not None:
            attr = self.objects_list.get(object_name)
            if mode == 'r' and str(attr)[0] == 1:
                return True
            if mode == 'w' and str(attr)[1] == 1:
                return True
            if mode == 'a' and str(attr)[2] == 1:
                return True
        elif subject_name is not None:
            attr = None
            if subject_type == 'u':
                attr = self.subjects_list_u.get(subject_name)
            elif subject_type == 'g':
                attr = self.subjects_list_g.get(subject_name)
            if mode == 'r' and str(attr)[0] == 1:
                return True
            if mode == 'w' and str(attr)[1] == 1:
                return True
        return False

    def append_journal(self, action_string):
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
