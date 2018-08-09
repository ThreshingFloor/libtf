import re

from .tf_log_base import TFLogBase

GENERIC_IPV4_REGEX = '(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'


class TFGenericLog(TFLogBase):

    def __init__(self, line_iterator, api_key, ports=None, base_uri=None, ip_query_batch_size=None):
        super(TFGenericLog, self).__init__(line_iterator, api_key, ports, base_uri, ip_query_batch_size)

        if not self.ports:
            raise Exception("Ports must be specified for generic parsing")

    def _analyze(self):
        """
        Apply the filter to the log file
        """
        for parsed_line in self.parsed_lines:
            if 'ip' in parsed_line:
                if parsed_line['ip'] in self.filter['ips']:
                    self.noisy_logs.append(parsed_line)
                else:
                    self.quiet_logs.append(parsed_line)
            else:
                self.quiet_logs.append(parsed_line)

    def _extract_line_features(self):
        """
        Parse raw log lines and convert it to a dictionary with extracted features.
        """
        for line in self.line_iterator:
            m = re.search(GENERIC_IPV4_REGEX, line)
            if m:
                data = {
                    'ip': m.group('ip'),
                    'raw': line
                }
                self.parsed_lines.append(data)

    def _extract_features(self):
        """
        Get the feature data from the log file necessary for a reduction
        """
        for parsed_line in self.parsed_lines:
            result = {'raw': parsed_line}

            result['ip'] = parsed_line['ip']
            if result['ip'] not in self.features['ips']:
                self.features['ips'].append(result['ip'])
