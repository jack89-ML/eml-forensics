"""Offline tests: Received hop tracing and security header heuristics."""

import email.message
import unittest

from eml_forensics import auth


class ReceivedTest(unittest.TestCase):
    HEADERS = [
        "from mail.example.org (mail.example.org [198.51.100.7]) "
        "by mx1.example.com with ESMTP id abc123; "
        "Sat, 10 Jan 2026 09:05:00 +0000",
        "from client.example.net (unknown [203.0.113.9]) "
        "by mail.example.org with SMTP id def456; "
        "Sat, 10 Jan 2026 09:00:00 +0000",
    ]

    def test_hops_oldest_to_newest(self):
        hops = auth.received_hops(self.HEADERS)
        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0].ip, "203.0.113.9")      # origin
        self.assertEqual(hops[1].ip, "198.51.100.7")     # final MX
        self.assertEqual(hops[1].delay_seconds, 300)

    def test_relay_fields(self):
        hops = auth.received_hops(self.HEADERS)
        self.assertEqual(hops[0].relay, "client.example.net")
        self.assertEqual(hops[1].by, "mx1.example.com")
        self.assertEqual(hops[1].protocol, "ESMTP")

    def test_ipv6_supported(self):
        line = ("from host.example.com (host.example.com [2001:db8::1]) "
                "by relay.example.net with ESMTP; "
                "Sat, 10 Jan 2026 10:00:00 +0000")
        hop = auth.parse_received_line(line, 0)
        self.assertEqual(hop.ip, "2001:db8::1")

    def test_unparseable_date_no_crash(self):
        hop = auth.parse_received_line("from a.example (a [192.0.2.1]) "
                                       "by b.example with ESMTP; now", 0)
        self.assertEqual(hop.ip, "192.0.2.1")
        self.assertEqual(hop.date, "")

    def test_folded_header_normalized(self):
        """A Received header folded across lines must keep its full date."""
        folded = ("from mail.example.org (mail.example.org [198.51.100.7])\n"
                  "\tby mx1.example.com with ESMTP id abc;\n"
                  " Sat, 10 Jan 2026 09:05:00 +0000")
        hop = auth.parse_received_line(folded, 0)
        self.assertEqual(hop.ip, "198.51.100.7")
        self.assertEqual(hop.by, "mx1.example.com")
        self.assertEqual(hop.date, "2026-01-10T09:05:00+00:00")


class SecurityHeadersTest(unittest.TestCase):
    def _message(self):
        message = email.message.EmailMessage()
        message["Received"] = self.Received = (
            "from mail.example.org by mx1.example.com with ESMTP; "
            "Sat, 10 Jan 2026 09:05:00 +0000")
        message["DKIM-Signature"] = (
            "v=1; a=rsa-sha256; d=example.org; s=selector1; "
            "h=from:to:subject; bh=abc")
        message["Received-SPF"] = (
            "pass (example.org: domain of alice@example.org) "
            "client-ip=203.0.113.1; envelope-from=alice@example.org")
        message["Authentication-Results"] = (
            "mx1.example.com; dkim=pass header.d=example.org; "
            "spf=pass smtp.mailfrom=alice@example.org")
        return message

    def test_dkim_summary(self):
        summary = auth.dkim_summary(self._message()["DKIM-Signature"])
        self.assertTrue(summary["present"])
        self.assertEqual(summary["domain"], "example.org")
        self.assertEqual(summary["selector"], "selector1")
        self.assertEqual(summary["sign_algo"], "rsa")
        self.assertEqual(summary["hash_algo"], "sha256")

    def test_spf_summary(self):
        summary = auth.spf_summary(self._message()["Received-SPF"])
        self.assertEqual(summary["result"], "pass")
        self.assertEqual(summary["mailfrom"], "alice@example.org")

    def test_auth_results_summary(self):
        summary = auth.auth_results_summary(
            self._message()["Authentication-Results"])
        self.assertEqual(summary["authserv_id"], "mx1.example.com")
        self.assertEqual(len(summary["results"]), 2)

    def test_analyze_headers_message(self):
        digest = auth.analyze_headers(self._message())
        self.assertEqual(digest["hop_count"], 1)
        self.assertEqual(digest["spf"]["result"], "pass")
        self.assertEqual(digest["dkim"]["domain"], "example.org")
        self.assertEqual(len(digest["authentication_results"]), 1)

    def test_empty_headers_are_neutral(self):
        digest = auth.analyze_headers(email.message.EmailMessage())
        self.assertEqual(digest["hop_count"], 0)
        self.assertEqual(digest["dkim"]["present"], False)


if __name__ == "__main__":
    unittest.main()
