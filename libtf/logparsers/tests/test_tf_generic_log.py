from unittest import TestCase

from mock import mock

from ..tf_generic_log import TFGenericLog


class TestTFGenericLog(TestCase):

    def setUp(self):
        self.tf_generic_log = TFGenericLog([
            '192.168.1.10 - - [13/Sep/2006:07:01:53 -0700] foo bar baz',
            '192.168.1.20 - - [28/Jul/2006:10:27:10 -0300] foo bar baz',
            '192.178.1.30 - - [28/Jul/2006:10:27:32 -0300] foo bar baz'
        ], 'foo', ports=['123:udp'])

    def test_ports_must_be_specified(self):
        with self.assertRaisesRegexp(Exception, "Ports must be specified for generic parsing"):
            TFGenericLog([], 'foo')

    def test_running_with_no_input_succeeds_but_tracks_no_log_lines(self):
        self.tf_generic_log = TFGenericLog([], 'foo', ports=['123:udp'])
        self.tf_generic_log.run()
        self.assertEqual(self.tf_generic_log.noisy_logs, [])
        self.assertEqual(self.tf_generic_log.quiet_logs, [])

    def test_can_filter_noisy_and_quiet_lines(self):
        with mock.patch.object(self.tf_generic_log, '_send_features', return_value={'ips': ['192.168.1.20']}):
            self.tf_generic_log.run()
            self.assertEqual(self.tf_generic_log.noisy_logs, [
                {'ip': '192.168.1.20',
                 'raw': '192.168.1.20 - - [28/Jul/2006:10:27:10 -0300] foo bar baz'}
            ])
            self.assertEqual(self.tf_generic_log.quiet_logs, [
                {'ip': '192.168.1.10',
                 'raw': '192.168.1.10 - - [13/Sep/2006:07:01:53 -0700] foo bar baz'},
                {'ip': '192.178.1.30',
                 'raw': '192.178.1.30 - - [28/Jul/2006:10:27:32 -0300] foo bar baz'}
            ])
