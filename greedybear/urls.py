# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path
from django.views.decorators.csrf import ensure_csrf_cookie


@ensure_csrf_cookie  # ty: ignore[invalid-argument-type]
def render_reactapp(request):
    return render(request, "index.html")


urlpatterns = [
    # admin
    path("admin/", admin.site.urls, name="admin"),
    re_path("^api/", include("api.urls")),
    re_path(r"^(?!api)$", render_reactapp),
    re_path(r"^(?!api)(?:.*)/?$", render_reactapp),
]
