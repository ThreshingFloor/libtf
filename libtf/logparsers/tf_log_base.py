import json
import sys

import requests
import six

from libtf.logparsers.tf_exceptions import TFAPIUnavailable


class TFLogBase(object):
    api_endpoint = '/v2/reducer/seen'
    default_base_uri = "https://api.threshingfloor.io"
    default_ip_query_batch_size = 1000

    def __init__(self, line_iterator, api_key, ports=None, base_uri=None, ip_query_batch_size=None):
        """
        :param line_iterator: Any iterator that emits log line strings
        :param api_key: The ThreshingFloor API key used for authentication
        :param ports: List of port/protocol strings to look for
        :param base_uri: The ThreshingFloor API base URI. Defaults to public ThreshingFloor API.
        :param ip_query_batch_size: How many IPs to query at a time. Defaults to default_ip_query_batch_size. Cannot
               be more than 1000.
        """
        self.line_iterator = line_iterator
        self.api_key = api_key

        self.features = {'ips': [], 'ports': []}

        # Add port and protocol
        if ports:
            for port in ports:
                item = {}
                item['port'], item['protocol'] = port.split(':', 2)
                item['port'] = int(item['port'])
                self.features['ports'].append(item)
            self.ports = list(self.features['ports'])
        else:
            self.ports = None

        self.base_uri = base_uri or self.default_base_uri
        self.ip_query_batch_size = ip_query_batch_size or self.default_ip_query_batch_size

        if self.ip_query_batch_size > 1000:
            raise Exception("ip_query_batch_size cannot be more than 1000")

        if self.base_uri.endswith('/'):
            raise Exception("base_uri cannot end in slash")

        self.parsed_lines = []
        self.filter = {'ips': [], 'ports': []}

        # Log lines that are unhandled
        self.unhandled_logs = []

        # Log lines that are considered noise
        self.noisy_logs = []

        # Log lines that are *not* considered noise
        self.quiet_logs = []

    def run(self):
        self._extract_line_features()
        self._extract_features()

        # Set the appropriate ports
        self.features['ports'] = self.ports

        # Set the filter for the file
        self._get_filter(self.features)

        # Perform the analysis operation
        self._analyze()

    def _extract_line_features(self):
        """
        Parse raw log lines and convert it to a dictionary with extracted features.
        """
        raise NotImplementedError("Must be implemented")

    def reduce(self, show_noisy=False):
        """
        Yield the reduced log lines

        :param show_noisy: If this is true, shows the reduced log file. If this is false, it shows the logs that
        were deleted.
        """
        if not show_noisy:
            for log in self.quiet_logs:
                yield log['raw'].strip()
        else:
            for log in self.noisy_logs:
                yield log['raw'].strip()

    def _get_filter(self, features):
        """
        Gets the filter for the features in the object

        :param features: The features of the syslog file
        """

        # This chops the features up into smaller lists so the api can handle them
        for ip_batch in (features['ips'][pos:pos + self.ip_query_batch_size]
                         for pos in six.moves.range(0, len(features['ips']), self.ip_query_batch_size)):
            # Query for each chunk and add it to the filter list
            query = {'ips': ip_batch, 'ports': features['ports']}
            self.filter['ips'] += self._send_features(query)['ips']

    def _send_features(self, features):
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
            sys.stderr.write("%s\n" % r.text)
            raise TFAPIUnavailable("Request failed and returned a status of: {STATUS_CODE}"
                                   .format(STATUS_CODE=r.status_code))

        return json.loads(r.text)

    def _analyze(self):
        raise NotImplementedError("Must be implemented")

    def _extract_features(self):
        raise NotImplementedError("Must be implemented")
