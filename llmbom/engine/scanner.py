import os


class ProjectScanner:

    def __init__(self, root_path):
        self.root_path = root_path

    def scan(self):
        file_list = []

        for root, _, files in os.walk(self.root_path):
            for file in files:
                file_list.append(os.path.join(root, file))

        return file_list
