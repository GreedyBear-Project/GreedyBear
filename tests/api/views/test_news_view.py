from unittest.mock import patch

import requests
from django.core.cache import cache
from feedparser import FeedParserDict

from api.views.utils import CACHE_KEY_GREEDYBEAR_NEWS, get_greedybear_news
from tests import CustomTestCase


class NewsTestCase(CustomTestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    @patch("api.views.utils.feedparser.parse")
    def test_returns_cached_data(self, mock_parse):
        cached_data = [
            {
                "title": "GreedyBear Cached",
                "date": "Thu, 29 Jan 2026 00:00:00 GMT",
                "link": "https://example.com",
                "subtext": "cached content",
            }
        ]
        cache.set(CACHE_KEY_GREEDYBEAR_NEWS, cached_data, 300)

        result = get_greedybear_news()

        self.assertEqual(result, cached_data)
        mock_parse.assert_not_called()

    @patch("api.views.utils.feedparser.parse")
    def test_sorts_posts_by_date_desc(self, mock_parse):
        mock_parse.return_value = FeedParserDict(
            entries=[
                FeedParserDict(
                    title="GreedyBear Old",
                    summary="old post",
                    published="Wed, 01 Jan 2026 00:00:00 GMT",
                    published_parsed=(2026, 1, 1, 0, 0, 0, 0, 0, 0),
                    link="https://example.com/old",
                ),
                FeedParserDict(
                    title="GreedyBear New",
                    summary="new post",
                    published="Thu, 29 Jan 2026 00:00:00 GMT",
                    published_parsed=(2026, 1, 29, 0, 0, 0, 0, 0, 0),
                    link="https://example.com/new",
                ),
            ]
        )

        result = get_greedybear_news()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["title"], "GreedyBear New")
        self.assertEqual(result[1]["title"], "GreedyBear Old")

    @patch("api.views.utils.feedparser.parse")
    def test_truncates_long_summary(self, mock_parse):
        long_summary = "word " * 100
        mock_parse.return_value = FeedParserDict(
            entries=[
                FeedParserDict(
                    title="GreedyBear Long Post",
                    summary=long_summary,
                    published="Thu, 29 Jan 2026 00:00:00 GMT",
                    published_parsed=(2026, 1, 29, 0, 0, 0, 3, 29, 0),
                    link="https://example.com",
                )
            ]
        )

        result = get_greedybear_news()
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["subtext"].endswith("..."))
        self.assertLessEqual(len(result[0]["subtext"]), 184)

    @patch("api.views.utils.feedparser.parse")
    def test_skips_entries_without_published_date(self, mock_parse):
        mock_parse.return_value = FeedParserDict(
            entries=[
                FeedParserDict(
                    title="GreedyBear No Date",
                    summary="missing date",
                    link="https://example.com",
                )
            ]
        )

        result = get_greedybear_news()
        self.assertEqual(result, [])

    @patch("api.views.utils.feedparser.parse")
    def test_handles_feed_failure_gracefully(self, mock_parse):
        mock_parse.side_effect = Exception("Feed error")
        result = get_greedybear_news()
        self.assertEqual(result, [])

    @patch("api.views.utils.feedparser.parse")
    def test_results_are_cached_after_first_call(self, mock_parse):
        mock_parse.return_value = FeedParserDict(
            entries=[
                FeedParserDict(
                    title="GreedyBear Cached Test",
                    summary="cache test",
                    published="Thu, 29 Jan 2026 00:00:00 GMT",
                    published_parsed=(2026, 1, 29, 0, 0, 0, 3, 29, 0),
                    link="https://example.com",
                )
            ]
        )

        # first calling hits feed
        result1 = get_greedybear_news()
        self.assertEqual(len(result1), 1)

        # resetting mock to ensure cache is used
        mock_parse.reset_mock()

        # second call should use cache
        result2 = get_greedybear_news()
        self.assertEqual(result1, result2)
        mock_parse.assert_not_called()

    @patch("api.views.utils.requests.get")
    def test_feed_request_timeout_returns_empty_list(self, mock_get):
        mock_get.side_effect = requests.Timeout()

        result = get_greedybear_news()

        self.assertEqual(result, [])
