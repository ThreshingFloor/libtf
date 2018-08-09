from unittest import TestCase

from mock import mock

from ..tf_auth_log import TFAuthLog


class TestTFAuthLog(TestCase):

    def setUp(self):
        self.tf_auth_log = TFAuthLog([
            'Feb 20 21:54:44 localhost sshd[3402]: Accepted publickey for john from 199.2.2.2 port 63673 ssh2: RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84',
            'Feb 21 00:13:35 localhost sshd[7483]: Accepted password for kat from 201.1.33.12 port 58803 ssh2',
            'Feb 20 21:54:44 localhost sshd[3402]: Accepted publickey for chuck from 10.0.2.2 port 63673 ssh2: RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84',
            'Feb 21 00:13:35 localhost sshd[7483]: Accepted password for sally from 192.168.33.1 port 58803 ssh2',
            'Feb 21 08:35:22 localhost sshd[5774]: Failed password for root from 116.31.116.24 port 29160 ssh2',
            'Feb 21 19:19:26 localhost sshd[16153]: Failed password for invalid user zuidberg from 142.0.45.14 port 52772 ssh2',
            'Feb 21 21:56:12 localhost sshd[3430]: Invalid user test from 10.0.2.2'
        ], 'foo')

    def test_ports_default_to_common_ssh_ports(self):
        self.assertEqual(self.tf_auth_log.ports, [{'port': 22, 'protocol': 'tcp'}])

    def test_running_with_no_input_succeeds_but_tracks_no_log_lines(self):
        self.tf_auth_log = TFAuthLog([], 'foo')
        self.tf_auth_log.run()
        self.assertEqual(self.tf_auth_log.noisy_logs, [])
        self.assertEqual(self.tf_auth_log.quiet_logs, [])

    def test_can_filter_noisy_and_quiet_lines(self):
        with mock.patch.object(self.tf_auth_log, '_send_features', return_value={'ips': ['10.0.2.2',
                                                                                         '192.168.33.1',
                                                                                         '116.31.116.24',
                                                                                         '142.0.45.14',
                                                                                         '10.0.2.2']}):

            self.tf_auth_log.run()
            self.assertEqual(self.tf_auth_log.noisy_logs, [
                {'timestamp': 1519202122, 'hostname': 'localhost', 'program': 'sshd', 'processid': '5774',
                 'message': 'Failed password for root from 116.31.116.24 port 29160 ssh2',
                 'raw': 'Feb 21 08:35:22 localhost sshd[5774]: Failed password for root from 116.31.116.24 port 29160 '
                        'ssh2'},
                {'timestamp': 1519240766, 'hostname': 'localhost', 'program': 'sshd', 'processid': '16153',
                 'message': 'Failed password for invalid user zuidberg from 142.0.45.14 port 52772 ssh2',
                 'raw': 'Feb 21 19:19:26 localhost sshd[16153]: Failed password for invalid user zuidberg from '
                        '142.0.45.14 port 52772 ssh2'},
                {'timestamp': 1519250172, 'hostname': 'localhost', 'program': 'sshd', 'processid': '3430',
                 'message': 'Invalid user test from 10.0.2.2',
                 'raw': 'Feb 21 21:56:12 localhost sshd[3430]: Invalid user test from 10.0.2.2'}]
)
            self.assertEqual(self.tf_auth_log.quiet_logs, [
                {'timestamp': 1519163684, 'hostname': 'localhost', 'program': 'sshd', 'processid': '3402',
                 'message': 'Accepted publickey for john from 199.2.2.2 port 63673 ssh2: '
                            'RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84',
                 'raw': 'Feb 20 21:54:44 localhost sshd[3402]: Accepted publickey for john from 199.2.2.2 port 63673 '
                        'ssh2: RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84'},
                {'timestamp': 1519172015, 'hostname': 'localhost', 'program': 'sshd', 'processid': '7483',
                 'message': 'Accepted password for kat from 201.1.33.12 port 58803 ssh2',
                 'raw': 'Feb 21 00:13:35 localhost sshd[7483]: Accepted password for kat from 201.1.33.12 port 58803 '
                        'ssh2'},
                {'timestamp': 1519163684, 'hostname': 'localhost', 'program': 'sshd', 'processid': '3402',
                 'message': 'Accepted publickey for chuck from 10.0.2.2 port 63673 ssh2: '
                            'RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84',
                 'raw': 'Feb 20 21:54:44 localhost sshd[3402]: Accepted publickey for chuck from 10.0.2.2 port 63673 '
                        'ssh2: RSA 39:33:99:e9:a0:dc:f2:33:a3:e5:72:3b:7c:3a:56:84'},
                {'timestamp': 1519172015, 'hostname': 'localhost', 'program': 'sshd', 'processid': '7483',
                 'message': 'Accepted password for sally from 192.168.33.1 port 58803 ssh2',
                 'raw': 'Feb 21 00:13:35 localhost sshd[7483]: Accepted password for sally from 192.168.33.1 port 58803'
                        ' ssh2'}])
