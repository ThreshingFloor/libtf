import datetime
import json
import re
import time

import requests
import six

from .tf_exceptions import TFAPIUnavailable


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

AUTH_LOG_REGEX = (
        r"^((?:\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?"
        r"|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b\s+(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])"
        r"(?:(?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:(?:[0-5]?[0-9]|60)(?:[:\.,][0-9]+)?)))) (?:<(?:[0-9]+)."
        r"(?:[0-9]+)> )\s+?((?:[a-zA-Z0-9._-]+)) ([\w\._/%-]+)(?:\[((?:[1-9][0-9]*))\])?: (.*)")

COMPILED_AUTH_LOG_REGEX = re.compile(AUTH_LOG_REGEX)


class TFAuthLog(object):
    api_endpoint = '/v2/reducer/seen'

    def __init__(self, stream, api_key, base_uri="https://api.threshingfloor.io"):
        """
        :param stream: A file-like object for reading log lines
        :param api_key: The ThreshingFloor API key used for authentication
        :param base_uri: The ThreshingFloor API base URI. Defaults to public ThreshingFloor API.
        """
        self.stream = stream
        self.api_key = api_key
        self.base_uri = base_uri

        self.year = datetime.datetime.now().year
        self.unhandled_logs = []
        self.features = {}
        self.parsed_log = []
        self.filter = {'ips': [], 'ports': []}
        self.ips_to_pids = {}

        # quietLogs are logs that have had noise removed
        self.quiet_logs = []

        # noisyLogs are logs that we think are noise
        self.noisy_logs = []

        # alertLogs are logs where we think a noisy actor managed to do something bad
        # For example, if someone has a successful auth attempt, but they
        # are known to be brute forcing ssh servers, they may have successfully broken in
        self.alert_logs = []

        self.parsed_log = self.as_dict()

        # Get the features from the file
        self._extract_features()

        # Set the appropriate ports
        self.features['ports'] = [{'port': 22, 'protocol': 'tcp'}]

        # Set the filter for the file
        self._get_filter(self.features)

        # Perform the analysis operation
        self._analyze()

    def reduce(self, show_noisy=False):
        """
        Print the reduced log file

        :param show_noisy: If this is true, shows the reduced log file. If this is false, it shows the logs that
        were deleted.
        """
        if not show_noisy:
            for log in self.quiet_logs:
                yield log['raw'].strip()
        else:
            for log in self.noisy_logs:
                yield log['raw'].strip()

    def _analyze(self):
        """
        Apply the filter to the stream
        """
        pids = []

        for ip in self.filter['ips']:
            if ip in self.ips_to_pids:
                for pid in self.ips_to_pids[ip]:
                    pids.append(pid)

        for line in self.parsed_log:
            if line['processid'] in pids:
                self.noisy_logs.append(line)
            else:
                self.quiet_logs.append(line)

    def _extract_features(self):
        """
        Extracts and sets the feature data from the log file necessary for a reduction
        """
        for line in self.parsed_log:

            # If it's ssh, we can handle it
            if line['program'] == 'sshd':
                result = self._parse_auth_message(line['message'])

                # Add the ip if we have it
                if 'ip' in result:
                    self.features['ips'].append(result['ip'])

                    # If we haven't seen the ip, add it
                    if result['ip'] not in self.ips_to_pids:
                        # Make the value a list of pids
                        self.ips_to_pids[result['ip']] = [line['processid']]
                    else:
                        # If we have seen the ip before, add the pid if it's a new one
                        if line['processid'] not in self.ips_to_pids[result['ip']]:
                            self.ips_to_pids[result['ip']].append(line['processid'])

    def as_dict(self):
        """
        Parse a valid log file and convert it to a dictionary with extracted features.

        :return: List of dictionaries containing log lines and extracted features
        """
        parsed_syslog = []

        for line in self.stream:
            m = COMPILED_AUTH_LOG_REGEX.match(line)
            if m:
                data = {
                    'timestamp': self._to_epoch(m.group(1)),
                    'hostname': m.group(2),
                    'program': m.group(3),
                    'processid': m.group(4),
                    'message': m.group(5),
                    'raw': line
                }

                parsed_syslog.append(data)
            else:
                pass

        return parsed_syslog

    def _to_epoch(self, ts):
        """
        Adds a year to the syslog timestamp because syslog doesn't use years

        :param ts: The timestamp to add a year to
        :return: Date/time string that includes a year
        """

        year = self.year
        tmpts = "%s %s" % (ts, str(self.year))
        new_time = int(time.mktime(time.strptime(tmpts, "%b %d %H:%M:%S %Y")))

        # If adding the year puts it in the future, this log must be from last year
        if new_time > int(time.time()):
            year -= 1
            tmpts = "%s %s" % (ts, str(year))
            new_time = int(time.mktime(time.strptime(tmpts, "%b %d %H:%M:%S %Y")))

        return new_time

    def _parse_auth_message(self, auth_message):
        """
        Parse an auth message to see if we have ip addresses or users that we care about

        :param auth_message: The auth message to parse
        :return: Result
        """
        result = {}

        has_matched = False

        for regex in REGEXES_INVALID_USER:
            # Check for the invalid user/ip messages
            m = re.search(regex, auth_message)

            if m and not has_matched:
                has_matched = True

                # Save the username and IP
                result['username'] = m.group('user')
                result['ip'] = m.group('ip')

        for regex in REGEXES_INVALID_IP:
            # Check for the invalid ip messages
            m = re.search(regex, auth_message)

            if m and not has_matched:
                has_matched = True

                # Save the  IP
                result['ip'] = m.group('ip')                        

        for regex in REGEXES_IGNORE:
            # Check for messages we want to ignore
            m = re.search(regex, auth_message)

            if m and not has_matched:
                has_matched = True

                # Do nothing
                pass

        # If it's an ssh log and we don't know what it is, handle that
        if not has_matched:
            self._unhandled_auth_log(auth_message)

        return result

    def _unhandled_auth_log(self, auth_message):
        """
        Stores a line that is unhandled

        :param auth_message: The parsed auth log line that we don't know how to handle
        """
        self.unhandled_logs.append(auth_message)

    def _get_filter(self, features):
        """
        Gets the filter for the features in the object

        :param features: The features of the syslog file
        """

        # This chops the features up into smaller lists so the api can handle them
        size = 10000
        for featureChunk in (features['ips'][pos:pos + size] for pos in six.moves.range(0, len(features['ips']), size)):
            # Query for each chunk and add it to the filter list
            query = {'ips': featureChunk, 'ports': features['ports']}
            self.filter['ips'] += self._send_auth_feature_query(query)['ips']

    def _send_auth_feature_query(self, features):
        """
        Send a query to the backend api with a list of observed features in this log file

        :param features: Features found in the log file
        :return: Response text from ThreshingFloor API
        """
        
        # Hit the auth endpoint with a list of features
        try:
            r = requests.post(self.base_uri + self.api_endpoint, json=features, headers={'x-api-key': self.api_key})
        except requests.exceptions.ConnectionError:
            raise TFAPIUnavailable("The ThreshingFloor API appears to be unavailable.")

        if r.status_code != 200:
            print(r.text)
            raise TFAPIUnavailable("Request failed and returned a status of: {STATUS_CODE}"
                                   .format(STATUS_CODE=r.status_code))

        return json.loads(r.text)
