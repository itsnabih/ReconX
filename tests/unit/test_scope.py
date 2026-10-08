"""Unit tests for the scope validator."""

import unittest

from reconx.scope import ScopeReason, ScopeValidator


def make_validator() -> ScopeValidator:
    return ScopeValidator(
        allowed_domains=["example.com", "*.example.com"],
        allowed_ips=["192.0.2.0/24", "2001:db8::/32"],
        excluded_domains=["payment.example.com"],
        excluded_ips=["192.0.2.50"],
    )


class TestPolicyConstruction(unittest.TestCase):
    def test_empty_allowed_scope_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScopeValidator(excluded_domains=["example.com"])

    def test_invalid_wildcard_rejected(self) -> None:
        for pattern in ["ex*mple.com", "*example.com", "*", "a.*.example.com"]:
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                ScopeValidator(allowed_domains=[pattern])

    def test_invalid_domain_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScopeValidator(allowed_domains=["bad_domain!.com"])

    def test_non_strict_cidr_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScopeValidator(allowed_ips=["192.0.2.5/24"])

    def test_invalid_ip_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ScopeValidator(allowed_ips=["999.0.0.1"])


class TestDomainMatching(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = make_validator()

    def test_exact_domain(self) -> None:
        decision = self.scope.check("example.com")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.ALLOWED_DOMAIN)
        self.assertEqual(decision.detail, "example.com")

    def test_normalization(self) -> None:
        for target in ["EXAMPLE.COM", "example.com.", "https://example.com/", "example.com:8443"]:
            with self.subTest(target=target):
                decision = self.scope.check(target)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.host, "example.com")

    def test_wildcard_matches_subdomains(self) -> None:
        for target in ["www.example.com", "a.b.example.com"]:
            with self.subTest(target=target):
                decision = self.scope.check(target)
                self.assertTrue(decision.allowed)
                self.assertEqual(decision.detail, "*.example.com")

    def test_wildcard_does_not_match_apex(self) -> None:
        scope = ScopeValidator(allowed_domains=["*.example.com"])
        self.assertFalse(scope.check("example.com").allowed)
        self.assertTrue(scope.check("api.example.com").allowed)

    def test_exact_does_not_match_subdomain(self) -> None:
        scope = ScopeValidator(allowed_domains=["example.com"])
        self.assertEqual(scope.check("www.example.com").reason, ScopeReason.NOT_IN_SCOPE)

    def test_suffix_lookalikes_rejected(self) -> None:
        for target in ["notexample.com", "example.com.evil.net", "example.co"]:
            with self.subTest(target=target):
                self.assertEqual(self.scope.check(target).reason, ScopeReason.NOT_IN_SCOPE)

    def test_excluded_domain_wins(self) -> None:
        decision = self.scope.check("https://payment.example.com/login")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.EXCLUDED_DOMAIN)

    def test_excluded_wildcard(self) -> None:
        scope = ScopeValidator(allowed_domains=["*.example.com"], excluded_domains=["*.internal.example.com"])
        self.assertEqual(scope.check("db.internal.example.com").reason, ScopeReason.EXCLUDED_DOMAIN)
        self.assertTrue(scope.check("internal.example.com").allowed)

    def test_url_userinfo_uses_real_host(self) -> None:
        decision = self.scope.check("http://example.com@evil.net/")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.host, "evil.net")

    def test_idn_host_normalized(self) -> None:
        scope = ScopeValidator(allowed_domains=["*.example.com"])
        decision = scope.check("bücher.example.com")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.host, "xn--bcher-kva.example.com")


class TestIPMatching(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = make_validator()

    def test_ip_in_cidr(self) -> None:
        decision = self.scope.check("192.0.2.10")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, ScopeReason.ALLOWED_IP)
        self.assertEqual(decision.detail, "192.0.2.0/24")

    def test_ip_outside_cidr(self) -> None:
        self.assertEqual(self.scope.check("198.51.100.1").reason, ScopeReason.NOT_IN_SCOPE)

    def test_excluded_ip_wins(self) -> None:
        for target in ["192.0.2.50", "http://192.0.2.50:8080/", "::ffff:192.0.2.50"]:
            with self.subTest(target=target):
                self.assertEqual(self.scope.check(target).reason, ScopeReason.EXCLUDED_IP)

    def test_ipv6(self) -> None:
        self.assertTrue(self.scope.check("2001:db8::1").allowed)
        self.assertTrue(self.scope.check("http://[2001:db8::1]:8080/").allowed)
        self.assertFalse(self.scope.check("2001:db9::1").allowed)

    def test_ip_not_matched_by_domain_rules(self) -> None:
        scope = ScopeValidator(allowed_domains=["example.com"])
        self.assertFalse(scope.check("192.0.2.10").allowed)


class TestInvalidTargets(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = make_validator()

    def test_malformed_targets_fail_closed(self) -> None:
        targets = [
            "",
            "   ",
            "-oX/tmp/out example.com",
            "example.com; id",
            "example.com\nevil.net",
            "$(id).example.com",
            "192.0.2.0/24",
            "example.com/path",
            "user@example.com",
            "example.com:99999",
            "example.com:abc",
            "exa_mple.example.com",
            "127.1",
            "0x7f000001",
            "fe80::1%eth0",
            "file:///etc/passwd",
        ]
        for target in targets:
            with self.subTest(target=target):
                decision = self.scope.check(target)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)
                self.assertTrue(decision.detail)


class TestRedirectValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = make_validator()

    def test_relative_redirect_stays_in_scope(self) -> None:
        decision = self.scope.check_redirect("https://example.com/a", "/login")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.target, "https://example.com/login")

    def test_absolute_redirect_in_scope(self) -> None:
        self.assertTrue(self.scope.check_redirect("https://example.com/", "https://www.example.com/").allowed)

    def test_redirect_to_out_of_scope_host(self) -> None:
        decision = self.scope.check_redirect("https://example.com/", "https://evil.net/")
        self.assertEqual(decision.reason, ScopeReason.NOT_IN_SCOPE)

    def test_scheme_relative_redirect(self) -> None:
        decision = self.scope.check_redirect("https://example.com/", "//evil.net/x")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.host, "evil.net")

    def test_redirect_to_excluded_host(self) -> None:
        decision = self.scope.check_redirect("https://example.com/", "https://payment.example.com/")
        self.assertEqual(decision.reason, ScopeReason.EXCLUDED_DOMAIN)

    def test_redirect_to_non_http_scheme(self) -> None:
        for location in ["file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)"]:
            with self.subTest(location=location):
                decision = self.scope.check_redirect("https://example.com/", location)
                self.assertEqual(decision.reason, ScopeReason.DISALLOWED_SCHEME)

    def test_redirect_with_backslash_rejected(self) -> None:
        decision = self.scope.check_redirect("https://example.com/", "https:\\\\evil.net")
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)

    def test_invalid_redirect_source(self) -> None:
        decision = self.scope.check_redirect("example.com", "/x")
        self.assertEqual(decision.reason, ScopeReason.INVALID_TARGET)


class TestDiscoveredAssets(unittest.TestCase):
    def test_discovery_does_not_expand_scope(self) -> None:
        scope = ScopeValidator(allowed_domains=["example.com"])
        discovered = ["mail.example.com", "93.184.216.34", "cdn.example-cdn.net", "example.org"]
        for asset in discovered:
            with self.subTest(asset=asset):
                self.assertFalse(scope.check(asset).allowed)
        # Repeated validation of discovered assets leaves the policy unchanged.
        self.assertTrue(scope.check("example.com").allowed)
        self.assertFalse(scope.check("mail.example.com").allowed)

    def test_discovered_in_scope_asset_accepted(self) -> None:
        scope = ScopeValidator(allowed_domains=["*.example.com"], allowed_ips=["192.0.2.0/24"])
        self.assertTrue(scope.check("mail.example.com").allowed)
        self.assertTrue(scope.check("192.0.2.25").allowed)
