from .tf_generic_log import TFGenericLog


class TFHttpLog(TFGenericLog):

    def __init__(self, line_iterator, api_key, ports=None, base_uri=None):
        # Default to commonly used HTTP ports if not specified
        if not ports:
            ports = ["80:tcp", "8080:tcp", "443:tcp"]

        super(TFHttpLog, self).__init__(line_iterator, api_key, ports, base_uri)
