# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import re

import pytest

from greedybear.regex import REGEX_DOMAIN, REGEX_PASSWORD


@pytest.mark.parametrize(
    "value",
    ["example.com", "a", "sub.example.co.uk", "xn--bcher-kva.example"],
)
def test_regex_domain_matches_hostnames(value):
    assert re.fullmatch(REGEX_DOMAIN, value)


@pytest.mark.parametrize(
    "value",
    ["", "example.com/path", "bad_domain.com", "not a domain", "2001:db8::1"],
)
def test_regex_domain_rejects_non_hostnames(value):
    assert re.fullmatch(REGEX_DOMAIN, value) is None


@pytest.mark.parametrize("value", ["averystrongpassword", "greedybeargreedybear$", "Password1234"])
def test_regex_password_accepts_policy(value):
    assert re.fullmatch(REGEX_PASSWORD, value)


@pytest.mark.parametrize("value", ["short", "123456789012", "has space word", "Greedy Bear Password 123"])
def test_regex_password_rejects_policy(value):
    assert re.fullmatch(REGEX_PASSWORD, value) is None
