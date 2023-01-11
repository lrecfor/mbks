class File:

    def __init__(self, file_name, owner_name, permissions):
        self.name = file_name
        self.owner = owner_name
        self.owner_p = permissions[0]
        self.group_p = permissions[1]
        self.others_p = permissions[2]


class Files:

    def __init__(self):
        self.files = list()

    def append_file(self, file_name, owner_name, permissions):
        self.files.append(File(file_name, owner_name, permissions))
