from unittest import TestCase

import mock

from ..tf_log_base import TFLogBase


class TestTFLogBase(TestCase):

    def test_defaults_to_public_tf_api(self):
        tf_log = TFLogBase([], 'foo')
        self.assertEqual(tf_log.base_uri, "https://api.threshingfloor.io")

    def test_base_uri_cannot_end_in_slash(self):
        with self.assertRaisesRegexp(Exception, "base_uri cannot end in slash"):
            TFLogBase([], 'foo', base_uri='http://asdf.com/')

    def test_ip_query_batch_size_cannot_be_greater_than_1000(self):
        with self.assertRaisesRegexp(Exception, "ip_query_batch_size cannot be more than 1000"):
            TFLogBase([], 'foo', ip_query_batch_size=1001)

    def test_extract_line_features_must_be_defined(self):
        tf_log = TFLogBase([], 'foo')
        with self.assertRaisesRegexp(NotImplementedError, "Must be implemented"):
            tf_log._extract_line_features()

    def test_extract_features_must_be_defined(self):
        tf_log = TFLogBase([], 'foo')
        with self.assertRaisesRegexp(NotImplementedError, "Must be implemented"):
            tf_log._extract_features()

    def test_analyze_must_be_defined(self):
        tf_log = TFLogBase([], 'foo')
        with self.assertRaisesRegexp(NotImplementedError, "Must be implemented"):
            tf_log._analyze()

    def test_can_iterate_over_reduced_log_lines(self):
        tf_log = TFLogBase([], 'foo')
        tf_log.quiet_logs = [{'raw': 'a'}, {'raw': 'b'}, {'raw': 'c'}]
        tf_log.noisy_logs = [{'raw': 'x'}, {'raw': 'y'}, {'raw': 'z'}]
        self.assertEqual(list(tf_log.reduce()), ['a', 'b', 'c'])
        self.assertEqual(list(tf_log.reduce(show_noisy=True)), ['x', 'y', 'z'])

    def test_can_batch_ip_queries_for_filter(self):
        features = {'ips': ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6'],
                    'ports': [22, 2222]}

        tf_log = TFLogBase([], 'foo', ip_query_batch_size=1)
        with mock.patch.object(tf_log, '_send_features') as mock_send_features:
            tf_log._get_filter(features)
            self.assertEqual(mock_send_features.call_args_list, [mock.call({'ips': ['1.1.1.1'], 'ports': [22, 2222]}),
                                                                 mock.call({'ips': ['2.2.2.2'], 'ports': [22, 2222]}),
                                                                 mock.call({'ips': ['3.3.3.3'], 'ports': [22, 2222]}),
                                                                 mock.call({'ips': ['4.4.4.4'], 'ports': [22, 2222]}),
                                                                 mock.call({'ips': ['5.5.5.5'], 'ports': [22, 2222]}),
                                                                 mock.call({'ips': ['6.6.6.6'], 'ports': [22, 2222]})])

        tf_log = TFLogBase([], 'foo', ip_query_batch_size=5)
        with mock.patch.object(tf_log, '_send_features') as mock_send_features:
            tf_log._get_filter(features)
            self.assertEqual(mock_send_features.call_args_list, [
                mock.call({'ips': ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'], 'ports': [22, 2222]}),
                mock.call({'ips': ['6.6.6.6'], 'ports': [22, 2222]})])
