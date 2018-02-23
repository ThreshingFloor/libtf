import re
import time, datetime, pytz
import requests
import json
import sys
from TFExceptions import *
from TFGenericLog import TFGenericLog

class TFHttpLog:

    ################################
    # Description:
    #   Initializer for the TFHttpLog object. Pass it a fileName and it will handle
    #   reduction for http access logs.
    #
    # Params:
    #   logfile - The array of lines in the logfile we are analyzing
    #   apiKey - The api key pulled from the ~/.tf.cfg file
    #   baseUri - The base URI of the ThreshingFloor API, as stored in the ~/.tf.cfg file
    ################################

    def __init__(self, logfile, apiKey, baseUri="https://api.threshingfloor.io"):

        self.reducer = TFGenericLog(logfile, ["80:tcp", "8080:tcp"], apiKey)

    ################################
    # Description:
    #   Print the reduced log file
    #
    # Params
    #   showQuietLogs - If this is true, shows the reduced log file. If this is false, it shows the logs that were deleted.
    #
    ################################

    def reduce(self, showNoisy=False):
        return self.reducer.reduce(showNoisy)
