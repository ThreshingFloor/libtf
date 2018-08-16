class TFException(Exception):
    pass


class TFAPIUnavailable(Exception):
    pass


class TFLogParsingException(Exception):
    def __init__(self, type):
        self.type = type
