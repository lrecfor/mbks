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
