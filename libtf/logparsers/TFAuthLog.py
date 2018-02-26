import re
import time
import requests
import json
from dateutil.relativedelta import relativedelta
import datetime
from TFExceptions import *


class TFAuthLog:

    ################################
    # Description:
    #   Constructor for the TFAuthLog object. Pass it a fileName and it will handle
    #   reduction for Auth events.
    #
    # Params:
    #   logfile - The array of log lines to be reduced
    #   apiKey - The api key pulled from the ~/.tf.cfg file
    #   baseUri - The base URI of the ThreshingFloor API, as stored in the ~/.tf.cfg file
    #   year - The year we should assume the log file is from
    ################################

    def __init__(self, logfile, apiKey, baseUri="https://api.threshingfloor.io", year=2018):
        self.BASE_URI = baseUri
        self.API_ENDPOINT = '/reducer/seen'
        self.apiKey = apiKey
        self.year = year
        self.unhandledLogs = []
        self.features = {}
        self.parsedLog = []
        self.filter = {'ips': [], 'ports': []}
        self.ipAndPid = {}

        # quietLogs are logs that have had noise removed
        self.quietLogs = []

        # noisyLogs are logs that we think are noise
        self.noisyLogs = []

        # alertLogs are logs where we think a noisy actor managed to do something bad
        # For example, if someone has a successful auth attempt, but they
        # are known to be brute forcing ssh servers, they may have successfully broken in
        self.alertLogs = []

        # Set the regex for syslog
        regex_string = (r"^((?:\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?"
                        r"|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b\s+(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])\s+"
                        r"(?:(?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:(?:[0-5]?[0-9]|60)(?:[:\.,][0-9]+)?)))) (?:<(?:[0-9]+).(?:[0-9]+)> )"
                        r"?((?:[a-zA-Z0-9._-]+)) ([\w\._/%-]+)(?:\[((?:[1-9][0-9]*))\])?: (.*)")
        self.SYSLOG_REGEX = re.compile(regex_string)

        self.parsedLog = self._jsonifySyslog(logfile)

        # Get the features from the file
        (self.features['ips'], self.ipAndPid) = self._getFeatures(self.parsedLog)

        # Set the appropriate ports
        self.features['ports'] = [{'port': 22, 'protocol': 'tcp'}]

        # These variables are now set:
        # self.unhandledLogs
        # self.features
        # self.parsedLog

        #Set the filter for the file
        self._getFilter(self.features)

        # self.filter is now set

        # Perform the analysis operation
        self._analyze(self.parsedLog, self.ipAndPid)

        # self.noisyLogs and self.quietLogs is now set


    ################################
    # Description:
    #   Print the reduced log file
    #
    # Params
    #   showQuietLogs - If this is true, shows the reduced log file. If this is false, it shows the logs that were deleted.
    #
    ################################

    def reduce(self, showNoisy=False):
        if not showNoisy:
            for log in self.quietLogs:
                yield log['raw'].strip()
        else:
            for log in self.noisyLogs:
                yield log['raw'].strip()



    ################################
    # Description:
    #   Apply the filter to the log file
    #
    ################################

    def _analyze(self, parsedLog, ipAndPid):

        # A list of pids to reduce 
        pids = []

        # Loop through the filter
        for ip in self.filter['ips']:

            # If we see the ip in our ip/pid dict
            if ip in ipAndPid:

                # Pull each pid and make sure we filter it later
                for pid in ipAndPid[ip]:
                    pids.append(pid)


        for line in parsedLog:

            # If we have a pid hit, filter it
            if line['processid'] in pids:
                self.noisyLogs.append(line)
            else:
                self.quietLogs.append(line)

    ################################
    # Description:
    #   Get the feature data from the log file necessary for a reduction
    # 
    # Params:
    #   parsedLog - The parsed syslog file
    #
    # Returns:
    #   A list of ip's from the log file
    ################################

    def _getFeatures(self, parsedLog):

        # The dict that holds the features of the log file
        ips = []

        ipAndPid = {}

        # Go through each line in the log
        for line in parsedLog:

            # If it's ssh, we can handle it
            if line['program'] == 'sshd':
                result = self._parseAuthMessage(line['message'])

                # Add the ip if we have it
                if 'ip' in result:
                    ips.append(result['ip'])

                    # Make a ip pid dict that has a list of pids associated with an ip

                    # If we havent seen the ip, add it
                    if result['ip'] not in ipAndPid:

                        # Make the value a list of pids
                        ipAndPid[result['ip']] = [line['processid']]
                    else:

                        # If we have seen the ip before, add the pid if it's a new one
                        if line['processid'] not in ipAndPid[result['ip']]:
                            ipAndPid[result['ip']].append(line['processid'])

            # TODO: We should handle other programs like telnet

        return (ips, ipAndPid)

    ################################
    # Description:
    #   Parse a valid syslog file and convert it to json.
    #
    # Params:
    #   logfile - The file to extract features from
    #
    # Returns:
    #   parsedLog - A dict object that contains all syslog metadata
    ################################

    def _jsonifySyslog(self, logfile):
        parsedSyslog = []

        for line in logfile:
            m = self.SYSLOG_REGEX.match(line)
            if m:
                data = {
                    'timestamp': self.toEpoch(m.group(1)),
                    'hostname': m.group(2),
                    'program': m.group(3),
                    'processid': m.group(4),
                    'message': m.group(5),
                    'raw': line
                }

                parsedSyslog.append(data)

            else:
                # TODO: Error check better
                pass
                raise TFLogParsingException('auth')

        return parsedSyslog

    ################################
    # Description:
    #   Add the most recent year's timestamp to the syslog timestamp because syslog doesn't use years
    #
    # Params:
    #   ts - The timestamp to add a year to
    #
    # Returns:
    #   response - A dict object that contains metadata for the auth message
    ################################

    def toEpoch(self, ts):

        # Add the current year
        theYear = datetime.datetime.now().year
        tmpts = "%s %s" % (ts, str(theYear))

        # Build the new time
        newTime = int(time.mktime(time.strptime(tmpts, "%b %d %H:%M:%S %Y")))

        # If adding the current year puts it in the future, this log must be from last year
        if newTime > int(time.time()):
            theYear -= 1

            # Build the new time
            tmpts = "%s %s" % (ts, str(theYear))
            newTime = int(time.mktime(time.strptime(tmpts, "%b %d %H:%M:%S %Y")))


        # Parse and return as integer
        return newTime

    ################################
    # Description:
    #   Parse an auth message to see if we have ip addresses or users that we care about
    #
    # Params:
    #   authMessage - The auth message we are trying to parse
    #
    # Returns:
    #   response - A dict object that contains metadata for the auth message
    ################################

    def _parseAuthMessage(self, authMessage):

        # TODO: We should save if it was a success or failure so we can make a bad ip with a successful login highly important

        # These are the regexes for auth messages that we can accurately extract from
        REGEXES_INVALID_USER = [
            "^Invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
            "^error: maximum authentication attempts exceeded for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2 \[preauth\]$",
            "^error: maximum authentication attempts exceeded for invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2 \[preauth\]$",
            "^Failed password for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2$",
            "^pam_unix\(sshd:auth\): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user=(?P<user>\w+)$",
            "^PAM \d+ more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user=(?P<user>\w+)$",
            "^message repeated \d+ times: \[ Failed password for (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2\]$",
            "^Failed password for invalid user (?P<user>\w+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2$"

        ]

        REGEXES_INVALID_IP = [
            "^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): 11: (Bye Bye|ok)?(\s)?\[preauth\]$",
            #"^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): 11: Bye Bye \[preauth\]$",
            #"^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}): 11: ok \[preauth\]$",
            "^Connection closed by (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \[preauth\]$",
            "^reverse mapping checking getaddrinfo for [\w|\.|-]+ \[(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] failed - POSSIBLE BREAK-IN ATTEMPT!$",
            "^Did not receive identification string from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
            "^Disconnected from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ \[preauth\]$",
            "^Received disconnect from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+:11: \[preauth\]$",
            "^Connection closed by (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ \[preauth\]$",
            "^pam_unix\(sshd:auth\): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        ]

        REGEXES_IGNORE = [
            "^input_userauth_request: invalid user \w+ \[preauth\]$",
            "^Disconnecting: Too many authentication failures for \w+ \[preauth\]$",
            "^fatal: Read from socket failed: Connection reset by peer \[preauth\]$",
            "^Accepted publickey for \w+ from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} port \d+ ssh2: RSA (\w\w:){15}\w\w$",
            "^pam_unix(sshd:session): session opened for user \w+ by (uid=\d+)$",
            "^Received disconnect from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}: 11: disconnected by user$",
            "^pam_unix\(sshd:session\): session closed for user \w+(\s by \s)?(\(uid=\d+\))?$",
            "^pam_unix\(sshd:session\): session opened for user \w+ by \(uid=\d+\)$",
            "^pam_unix\(sshd:auth\): check pass; user unknown$"
        ]

        result = {}

        hasMatched = False

        for REGEX in REGEXES_INVALID_USER:
            # Check for the invalid user/ip messages
            m = re.search(REGEX, authMessage)

            if m and not hasMatched:
                hasMatched = True

                # Save the username and IP
                result['username'] = m.group('user')
                result['ip'] = m.group('ip')

        for REGEX in REGEXES_INVALID_IP:
            # Check for the invalid ip messages
            m = re.search(REGEX, authMessage)

            if m and not hasMatched:
                hasMatched = True

                # Save the  IP
                result['ip'] = m.group('ip')                        

        for REGEX in REGEXES_IGNORE:
            # Check for messages we want to ignore
            m = re.search(REGEX, authMessage)

            if m and not hasMatched:
                hasMatched = True

                # Do nothing
                pass

        # If it's an ssh log and we don't know what it is, handle that
        if not hasMatched:
            self._unhandledAuthLog(authMessage)

        return result


    ################################
    # Description:
    #   If we have an auth log that we don't have a regex for, we need to add it to a list of unhandled log lines
    #
    # Params:
    #   authMessage - The parsed auth log line that we don't know how to handle 
    #
    ################################

    def _unhandledAuthLog(self, authMessage):
        self.unhandledLogs.append(authMessage)

    ################################
    # Description:
    #   Gets the filter for the features in the object
    #
    # Params:
    #   features - The features of the syslog file
    #
    # Returns:
    #   Nothing
    ################################

    def _getFilter(self, features):

        # This chops the features up into smaller lists so the api can handle them
        size = 10000
        for featureChunk in (features['ips'][pos:pos + size] for pos in xrange(0, len(features['ips']), size)):
            # Query for each chunk and add it to the filter list
            query = {'ips': featureChunk, 'ports': features['ports']}
            self.filter['ips'] += self._sendAuthFeatureQuery(query)['ips']

    ################################
    # Description:
    #   Send a query to the backend api with a list of observed features in this log file
    #
    # Params:
    #   features - The list of features we want to query
    #
    # Returns:
    #   logFilter - A list of features that should be filtered out of the log file
    ################################

    def _sendAuthFeatureQuery(self, features):
        
        # Hit the auth endpoint with a list of features
        try:
            r = requests.post(self.BASE_URI + self.API_ENDPOINT, data = json.dumps(features), headers={'x-api-key': self.apiKey})
        except requests.exceptions.ConnectionError as e:
            raise TFAPIUnavailable("The ThreshingFloor API appears to be unavailable.")

        # If we error, try and die gracefully
        if r.status_code != 200:
            print(r.text)
            raise TFAPIUnavailable("Request failed and returned a status of: {STATUS_CODE}".format(STATUS_CODE=r.status_code))

        return json.loads(r.text)




