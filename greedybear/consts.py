# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import time

SCANNER = "scanner"
PAYLOAD_REQUEST = "payload_request"

GET = "GET"
POST = "POST"

REGEX_DOMAIN = r"^[a-zA-Z\d-]{1,60}(\.[a-zA-Z\d-]{1,60})*$"
REGEX_IP = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
REGEX_PASSWORD = r"^(?=.*[a-zA-Z])\S{12,}$"

DOMAIN = "domain"
IP = "ip"

FIELDS_TO_EXTRACT = [
    "@timestamp",
    "body",
    "dest_port",
    "duration",
    "eventid",
    "geoip",
    "geoip_ext",
    "ip_rep",
    "message",
    "outfile",
    "password",
    "path",
    "post_data",
    "protocol",
    "session",
    "shasum",
    "src_ip",
    "t-pot_ip_ext",
    "timestamp",
    "type",
    "url",
    "username",
]


# Mass scanner service domains for reverse DNS filtering.
# If a PTR record ends with one of these, the IP is classified as a mass scanner.
MASS_SCANNER_DOMAINS = frozenset(
    {
        "shodan.io",
        "censys.io",
        "onyphe.net",
        "binaryedge.io",
        "shadowserver.org",
        "internet-census.org",
        "stretchoid.com",
        "internet-measurement.com",
        "recyber.net",
    }
)


# we used this const to implement news feature
RSS_FEED_URL = "https://greedybear-project.github.io/feed.xml"
CACHE_KEY_GREEDYBEAR_NEWS = "greedybear_news"
CACHE_TIMEOUT_SECONDS = 60 * 60

# tracking application start time
START_TIME = time.time()
