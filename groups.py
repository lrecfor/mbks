class Group:

    def __init__(self, name, participants, mark):
        self.name = name
        self.participants = participants
        self.mark = mark


class Groups:

    def __init__(self):
        self.groups = list()

    def append_group(self, group_name, participants, mark):
        self.groups.append(Group(group_name, participants, str(mark)))

    def delete_group(self, group_name):
        for group in self.groups:
            if group.name == group_name:
                self.groups.remove(group)

    def find(self, group_name, user_name):
        for group in self.groups:
            if group.name == group_name:
                if user_name in group.participants:
                    return True
                else:
                    return False
