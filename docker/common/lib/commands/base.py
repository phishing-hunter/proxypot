class BaseCommand:
    def __init__(self, fs, *args):
        self.fs = fs
        self.args = list(args)

    def start(self):

