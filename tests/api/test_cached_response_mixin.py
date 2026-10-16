from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from rest_framework.response import Response

from api.mixins import CachedResponseMixin


class CachedResponseMixinRenderTest(SimpleTestCase):
    def test_store_api_response_renders_only_once(self):
        renderer = Mock()
        renderer.render.return_value = b'{"ok":true}'

        response = Response({"ok": True})
        response.accepted_renderer = renderer
        response.accepted_media_type = "application/json"
        response.renderer_context = {}

        view = CachedResponseMixin()
        view.cache_key = "test-cache-key"

        with patch.object(view.cache, "set") as cache_set:
            self.assertTrue(view._store_api_response(response))

        self.assertEqual(renderer.render.call_count, 1)
        cache_set.assert_called_once()
        cached_value = cache_set.call_args.args[1]
        self.assertEqual(cached_value["content"], response.content)
