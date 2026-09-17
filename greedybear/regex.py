# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
REGEX_CVE_URL = r"//[a-zA-Z\d_-]{1,200}(?:\.[a-zA-Z\d_-]{1,200})+(?::\d{2,6})?(?:/[a-zA-Z\d_=-]{1,200})*(?:\.\w+)?"
REGEX_URL = REGEX_CVE_URL[2:]
REGEX_URL_PROTOCOL = r"(?:htt|ft|tc|lda)ps?:?" + REGEX_CVE_URL
# Cowrie session IDs are stored in a 64 bit BigIntegerField, so at most 16 hex digits
REGEX_COWRIE_SESSION_ID = r"[0-9a-fA-F]{1,16}"
