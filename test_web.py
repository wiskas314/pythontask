import unittest
from unittest.mock import patch, MagicMock


from web import ProxyServer

class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyServer(port=8080)
    def test_parse_host_port_http_default_port(self):
        first_line = "GET http://example.com/path HTTP/1.1"
        host, port = self.proxy.parse_host_port(first_line)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 80)

    def test_parse_host_port_http_custom_port(self):
        first_line = "GET http://example.com:8080/path HTTP/1.1"
        host, port = self.proxy.parse_host_port(first_line)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8080)

    def test_parse_host_port_https(self):
        first_line = "CONNECT example.com:443 HTTP/1.1"
        host, port = self.proxy.parse_host_port(first_line)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)

    def test_parse_host_port_invalid(self):
        first_line = "GET"
        with self.assertRaises(ValueError):
            self.proxy.parse_host_port(first_line)

    @patch('web.select.select')
    def test_relay_data(self, mock_select):
        client_sock = MagicMock()
        target_sock = MagicMock()


        mock_select.side_effect = [
            ([client_sock], [], []),
            ([client_sock], [], [])
        ]


        client_sock.recv.side_effect = [b"test payload", b""]

        self.proxy.relay_data(client_sock, target_sock)

        target_sock.sendall.assert_called_once_with(b"test payload")

        self.assertEqual(client_sock.recv.call_count, 2)


if __name__ == '__main__':
    unittest.main()
