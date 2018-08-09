import calendar
import datetime
import re
import sys
import time

from .tf_log_base import TFLogBase

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
    r"|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b\s+(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])\s+"
    r"(?:(?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:(?:[0-5]?[0-9]|60)(?:[:\.,][0-9]+)?)))) (?:<(?:[0-9]+).(?:[0-9]+)> )"
    r"?((?:[a-zA-Z0-9._-]+)) ([\w\._/%-]+)(?:\[((?:[1-9][0-9]*))\])?: (.*)")

COMPILED_AUTH_LOG_REGEX = re.compile(AUTH_LOG_REGEX)


class TFAuthLog(TFLogBase):

    def __init__(self, line_iterator, api_key, ports=None, base_uri=None):
        super(TFAuthLog, self).__init__(line_iterator, api_key, ports, base_uri)

        self.year = datetime.datetime.now().year
        self.ips_to_pids = {}

        # Default to standard SSH port if not specified
        if not self.ports:
            self.ports = [{'port': 22, 'protocol': 'tcp'}]

    def _extract_features(self):
        """
        Extracts and sets the feature data from the log file necessary for a reduction
        """
        for parsed_line in self.parsed_lines:

            # If it's ssh, we can handle it
            if parsed_line['program'] == 'sshd':
                result = self._parse_auth_message(parsed_line['message'])

                # Add the ip if we have it
                if 'ip' in result:
                    self.features['ips'].append(result['ip'])

                    # If we haven't seen the ip, add it
                    if result['ip'] not in self.ips_to_pids:
                        # Make the value a list of pids
                        self.ips_to_pids[result['ip']] = [parsed_line['processid']]
                    else:
                        # If we have seen the ip before, add the pid if it's a new one
                        if parsed_line['processid'] not in self.ips_to_pids[result['ip']]:
                            self.ips_to_pids[result['ip']].append(parsed_line['processid'])

    def _extract_line_features(self):
        """
        Parse raw log lines and convert it to a dictionary with extracted features.
        """
        for line in self.line_iterator:
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
                self.parsed_lines.append(data)

    def _analyze(self):
        """
        Decide which lines should be filtered out
        """
        pids = []

        for ip in self.filter['ips']:
            if ip in self.ips_to_pids:
                for pid in self.ips_to_pids[ip]:
                    pids.append(pid)

        for line in self.parsed_lines:
            if line['processid'] in pids:
                self.noisy_logs.append(line)
            else:
                self.quiet_logs.append(line)

    def _to_epoch(self, ts):
        """
        Adds a year to the syslog timestamp because syslog doesn't use years

        :param ts: The timestamp to add a year to
        :return: Date/time string that includes a year
        """

        year = self.year
        tmpts = "%s %s" % (ts, str(self.year))
        new_time = int(calendar.timegm(time.strptime(tmpts, "%b %d %H:%M:%S %Y")))

        # If adding the year puts it in the future, this log must be from last year
        if new_time > int(time.time()):
            year -= 1
            tmpts = "%s %s" % (ts, str(year))
            new_time = int(calendar.timegm(time.strptime(tmpts, "%b %d %H:%M:%S %Y")))

        return new_time

    def _parse_auth_message(self, auth_message):
        """
        Parse a message to see if we have ip addresses or users that we care about

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

                # Save the IP
                result['ip'] = m.group('ip')                        

        for regex in REGEXES_IGNORE:
            # Check for messages we want to ignore
            m = re.search(regex, auth_message)

            if m and not has_matched:
                has_matched = True

        # If it's an ssh log and we don't know what it is, handle that
        if not has_matched:
            sys.stderr.write("Unhandled auth message: %s\n" % auth_message)

        return result
