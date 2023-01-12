class Object:

    def __init__(self, object_name, owner_name, permissions):
        self.name = object_name
        self.owner = owner_name
        self.owner_p = permissions[0]
        self.group_p = permissions[1]
        self.others_p = permissions[2]


class Objects:

    def __init__(self):
        self.objects = list()

    def append_object(self, object_name, owner_name, permissions):
        self.objects.append(Object(object_name, owner_name, str(permissions)))
