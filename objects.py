class Object:

    def __init__(self, object_name, owner_name, permissions, mark):
        self.name = object_name
        self.owner = owner_name
        self.owner_p = permissions[0]
        self.group_p = permissions[1]
        self.others_p = permissions[2]
        self.mark = mark


class Objects:

    def __init__(self):
        self.objects = list()

    def append_object(self, object_name, owner_name, permissions, mark=0):
        self.objects.append(Object(object_name, owner_name, str(permissions), str(mark)))
