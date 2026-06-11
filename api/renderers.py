import csv
import io

from django.conf import settings
from django.db.models import QuerySet
from rest_framework.renderers import BaseRenderer, JSONRenderer

from api.views.utils import build_feed_dict, build_stix_bundle


class FeedJSONRenderer(JSONRenderer):
    """JSON feed renderer.
    When the `build_feed_envelope` context flag is set, it shapes the raw IOC
    rows into the {"iocs": [...], "license": ...} envelope.
    Any other payload (ASN list, pagination envelope) is rendered as plain JSON.
    """

    def render(self, data, accepted_media_type=None, renderer_context=None):
        context = renderer_context or {}
        if context.get("build_feed_envelope"):
            data = build_feed_dict(
                data,
                verbose=context.get("verbose", False),
                include_sensors=context.get("include_sensors", False),
            )
        return super().render(data, accepted_media_type, renderer_context)


class FeedRendererMixin(BaseRenderer):
    """Shared safety net for the non-JSON feed renderers."""

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if not isinstance(data, QuerySet):
            return JSONRenderer().render(data, accepted_media_type, renderer_context)
        return self.render_feed(data, accepted_media_type, renderer_context)

    def render_feed(self, data, accepted_media_type=None, renderer_context=None):
        raise NotImplementedError


class FeedTextRenderer(FeedRendererMixin):
    """Plain-text feed: one IOC value per line, prefixed by the license comment."""

    media_type = "text/plain"
    format = "txt"
    charset = None

    def render_feed(self, data, accepted_media_type=None, renderer_context=None):
        lines = [f"# {settings.FEEDS_LICENSE}"] if settings.FEEDS_LICENSE else []
        lines += [row[0] for row in data.values_list("name")]
        return "\n".join(lines).encode("utf-8")


class FeedCSVRenderer(FeedRendererMixin):
    """CSV feed: one IOC value per row, prefixed by the license comment."""

    media_type = "text/csv"
    format = "csv"
    charset = None

    def render_feed(self, data, accepted_media_type=None, renderer_context=None):
        rows = [[f"# {settings.FEEDS_LICENSE}"]] if settings.FEEDS_LICENSE else []
        rows += [list(row) for row in data.values_list("name")]
        buffer = io.StringIO()
        csv.writer(buffer, quoting=csv.QUOTE_NONE).writerows(rows)
        return buffer.getvalue().encode("utf-8")


class Stix21Renderer(FeedRendererMixin):
    """STIX 2.1 bundle feed (served as application/json)."""

    media_type = "application/json"
    format = "stix21"
    charset = None

    def render_feed(self, data, accepted_media_type=None, renderer_context=None):
        request = (renderer_context or {}).get("request")
        return build_stix_bundle(data, request=request).encode("utf-8")
