from enum import Enum


class Status(Enum):
    admin = 1
    ordinary = 2


class User:

    def __init__(self):
        self.log = None
        self.passwd = None
        self.path = None
        self.dir = None  # /home
        self.status = Status.ordinary
        self.group = None
