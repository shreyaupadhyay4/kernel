import ipaddress
import socket
import sys
import unittest
from types import SimpleNamespace

from collector.ebpf_agent import decode_socket_address, event_to_mapping


class CollectorTests(unittest.TestCase):
    def test_decodes_ipv4_connect_event(self) -> None:
        address = ipaddress.ip_address("192.0.2.10").packed
        raw = SimpleNamespace(
            type=2,
            ts=100,
            pid=20,
            ppid=10,
            uid=1000,
            comm=b"curl\0",
            family=socket.AF_INET,
            ipv4=int.from_bytes(address, byteorder=sys.byteorder),
            ipv6=bytes(16),
            port=socket.htons(443),
        )

        event = event_to_mapping(raw)

        self.assertEqual(event["event_type"], "connect")
        self.assertEqual(event["dest_ip"], "192.0.2.10")
        self.assertEqual(event["dest_port"], 443)

    def test_decodes_ipv6_address(self) -> None:
        address = ipaddress.ip_address("2001:db8::1").packed

        decoded_ip, decoded_port = decode_socket_address(
            socket.AF_INET6,
            address,
            socket.htons(8443),
        )

        self.assertEqual(decoded_ip, "2001:db8::1")
        self.assertEqual(decoded_port, 8443)


if __name__ == "__main__":
    unittest.main()
