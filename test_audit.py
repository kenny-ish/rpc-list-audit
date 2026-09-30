import unittest

from audit import classify_response, dns_verdict, endpoints

CHAINLIST = [{"chainId": 1, "name": "Ethereum Mainnet",
              "rpc": [{"url": "https://eth.example", "tracking": "none"}, {"url": "wss://eth.example/ws"}, {"tracking": "none"}]}]
ETHEREUM_LISTS = [{"chainId": 10, "name": "OP Mainnet", "rpc": ["https://op.example", "not a url"],
                   "faucets": ["https://faucet.example"]}]


class Endpoints(unittest.TestCase):
    def test_reads_chainlist_objects(self):
        self.assertEqual(endpoints(CHAINLIST), [(1, "Ethereum Mainnet", "https://eth.example"),
                                                (1, "Ethereum Mainnet", "wss://eth.example/ws")])

    def test_reads_plain_strings_and_skips_entries_without_a_host(self):
        self.assertEqual(endpoints(ETHEREUM_LISTS), [(10, "OP Mainnet", "https://op.example")])

    def test_other_fields_and_chain_filter(self):
        self.assertEqual(endpoints(ETHEREUM_LISTS, "faucets"), [(10, "OP Mainnet", "https://faucet.example")])
        self.assertEqual(endpoints(CHAINLIST + ETHEREUM_LISTS, chain_ids={10}), [(10, "OP Mainnet", "https://op.example")])


class DnsVerdict(unittest.TestCase):
    def test_gone_only_when_every_answer_is_nxdomain(self):
        self.assertEqual(dns_verdict([3, 3, 3, 3]), "gone")
        self.assertEqual(dns_verdict([3, 3, 0, 3]), "exists")

    def test_servfail_is_not_evidence(self):
        self.assertEqual(dns_verdict([2, 3, 3, 3]), "unclear")
        self.assertEqual(dns_verdict([]), "unclear")


class ClassifyResponse(unittest.TestCase):
    def test_location_independent_failures(self):
        self.assertEqual(classify_response(410, "", 1), ("dead", "HTTP 410 Gone"))
        self.assertEqual(classify_response(522, "", 1)[0], "dead")
        self.assertEqual(classify_response(403, '{"error":"Invalid API key"}', 1), ("dead", 'API key error: "Invalid API key"'))

    def test_wrong_chain_is_dead(self):
        self.assertEqual(classify_response(200, '{"jsonrpc":"2.0","id":1,"result":"0x38"}', 1),
                         ("dead", "answers for chain 56, listed under 1"))

    def test_matching_chain_is_ok(self):
        self.assertEqual(classify_response(200, '{"jsonrpc":"2.0","id":1,"result":"0x1"}', 1), ("ok", ""))

    def test_rate_limits_and_server_errors_are_not_reported(self):
        self.assertEqual(classify_response(429, "Too Many Requests", 1), ("unclear", "HTTP 429"))
        self.assertEqual(classify_response(503, "", 1), ("unclear", "HTTP 503"))
        self.assertEqual(classify_response(200, "<html>", 1), ("unclear", "not a JSON-RPC reply"))


if __name__ == "__main__":
    unittest.main()
