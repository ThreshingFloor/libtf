from .tf_generic_log import TFGenericLog


class TFHttpLog(object):

    def __init__(self, logfile, api_key, base_uri="https://api.threshingfloor.io"):
        """
        :param logfile: The array of lines in the logfile we are analyzing
        :param api_key: The api key pulled from the ~/.tf.cfg file
        :param base_uri: The base URI of the ThreshingFloor API
        """
        self.reducer = TFGenericLog(logfile, ["80:tcp", "8080:tcp"], api_key)

        # quietLogs are logs that have had noise removed
        self.quiet_logs = self.reducer.quietLogs

        # noisyLogs are logs that we think are noise
        self.noisy_logs = self.reducer.noisyLogs

        self.parsed_log = self.reducer.parsedLog
        self.unhandled_logs = self.reducer.unhandledLogs

        # alertLogs are logs where we think a noisy actor managed to do something bad
        # For example, if someone has a successful auth attempt, but they
        # are known to be brute forcing ssh servers, they may have successfully broken in
        self.alert_logs = []

    def reduce(self, show_noisy=False):
        """
        Print the reduced log file

        :param show_noisy: If this is true, shows the reduced log file. If this is false, it shows the logs that were
        deleted
        """
        return self.reducer.reduce(show_noisy)
