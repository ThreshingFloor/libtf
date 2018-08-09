from unittest import TestCase

from mock import mock

from ..tf_http_log import TFHttpLog


class TestTFHTTPLog(TestCase):

    def setUp(self):
        self.tf_http_log = TFHttpLog([
            '192.168.1.10 - - [13/Sep/2006:07:01:53 -0700] "PROPFIND /svn/1234/Extranet/branches/SOW-101 HTTP/1.1"'
            ' 401 587',
            '192.168.1.20 - - [28/Jul/2006:10:27:10 -0300] "GET /cgi-bin/try/ HTTP/1.0" 200 3395',
            '192.178.1.30 - - [28/Jul/2006:10:27:32 -0300] "GET /hidden/ HTTP/1.0" 404 7218'
        ], 'foo')

    def test_ports_default_to_common_http_ports(self):
        self.assertEqual(self.tf_http_log.ports, [{'port': 80, 'protocol': 'tcp'},
                                                  {'port': 8080, 'protocol': 'tcp'},
                                                  {'port': 443, 'protocol': 'tcp'}])

    def test_running_with_no_input_succeeds_but_tracks_no_log_lines(self):
        self.tf_http_log = TFHttpLog([], 'foo')
        self.tf_http_log.run()
        self.assertEqual(self.tf_http_log.noisy_logs, [])
        self.assertEqual(self.tf_http_log.quiet_logs, [])

    def test_can_filter_noisy_and_quiet_lines(self):
        with mock.patch.object(self.tf_http_log, '_send_features', return_value={'ips': ['192.168.1.20']}):
            self.tf_http_log.run()
            self.assertEqual(self.tf_http_log.noisy_logs, [
                {'ip': '192.168.1.20',
                 'raw': '192.168.1.20 - - [28/Jul/2006:10:27:10 -0300] "GET /cgi-bin/try/ HTTP/1.0" 200 3395'}
            ])
            self.assertEqual(self.tf_http_log.quiet_logs, [
                {'ip': '192.168.1.10',
                 'raw': '192.168.1.10 - - [13/Sep/2006:07:01:53 -0700] "PROPFIND /svn/1234/Extranet/branches/SOW-101 '
                        'HTTP/1.1" 401 587'},
                {'ip': '192.178.1.30',
                 'raw': '192.178.1.30 - - [28/Jul/2006:10:27:32 -0300] "GET /hidden/ HTTP/1.0" 404 7218'}
            ])
