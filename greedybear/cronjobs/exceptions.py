# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.


class RecoverableError(Exception):
    """
    Marker base for failures that are worth retrying.

    A windowed job that hits one of these keeps its watermark where it is, so the
    next run fetches the same time window again. Any other exception is treated
    as permanent: the window is recorded as failed and skipped, because retrying
    it would most likely fail the same way and stall extraction for good.
    """


class ElasticServerDownError(RecoverableError):
    """Raised when the Elasticsearch server is unreachable."""


class PayloadServerError(RecoverableError):
    """Raised when the tpot-payload-server cannot be reached."""
