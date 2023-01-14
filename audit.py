n = 5


class Audit:

    def __init__(self):
        # специальные атрибуты аудита у каждого объекта (например, аудит чтения, аудит записи, аудит дозаписи)
        self.objects_list = dict()
        self.journal = list()
        self.attr = dict()

    def append_journal(self, action_string):
        self.journal.append(action_string)
        if len(self.journal) == n:
            self.save_journal()

    def save_journal(self):
        with open("journal.txt", "w") as _:
            count = 0
            for line in self.journal:
                count += 1
                if count == len(self.journal):
                    _.writelines(str(line))
                else:
                    _.writelines(str(line) + "\n")

    def clear_journal(self):
        self.journal.clear()
