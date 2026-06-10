from datetime import timedelta

import django_filters
from django.db.models import QuerySet
from django.utils import timezone

from greedybear.models import IOC


class FeedsFilterSet(django_filters.FilterSet):
    asn = django_filters.NumberFilter(field_name="autonomous_system__asn")
    min_score = django_filters.NumberFilter(field_name="recurrence_probability", lookup_expr="gte")
    min_expected_interactions = django_filters.NumberFilter(field_name="expected_interactions", lookup_expr="gte")
    start_date = django_filters.DateFilter(field_name="last_seen", lookup_expr="gte")
    end_date = django_filters.DateFilter(field_name="last_seen", lookup_expr="lte")
    tag_key = django_filters.CharFilter(field_name="tags__key")
    tag_value = django_filters.CharFilter(field_name="tags__value", lookup_expr="icontains")

    attack_type = django_filters.CharFilter(method="filter_attack_type")
    ioc_type = django_filters.CharFilter(method="filter_ioc_type")
    port = django_filters.NumberFilter(method="filter_port")
    country_code = django_filters.CharFilter(method="filter_country_code")
    min_days_seen = django_filters.NumberFilter(method="filter_min_days_seen")
    max_age = django_filters.NumberFilter(method="filter_max_age")
    include_reputation = django_filters.Filter(method="filter_include_reputation")

    class Meta:
        model = IOC
        fields = []  # all filters are declared explicitly above

    def filter_attack_type(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        if value and value != "all":
            return queryset.filter(**{value: True})
        return queryset

    def filter_ioc_type(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        if value and value != "all":
            return queryset.filter(type=value)
        return queryset

    def filter_port(self, queryset: QuerySet, name: str, value: int) -> QuerySet:
        return queryset.filter(destination_ports__contains=[int(value)])

    def filter_country_code(self, queryset: QuerySet, name: str, value: str) -> QuerySet:
        return queryset.filter(attacker_country_code=value.upper())

    def filter_min_days_seen(self, queryset: QuerySet, name: str, value: int) -> QuerySet:
        if value and value > 1:
            return queryset.filter(number_of_days_seen__gte=value)
        return queryset

    def filter_include_reputation(self, queryset: QuerySet, name: str, value: list[str]) -> QuerySet:
        if value:
            return queryset.filter(ip_reputation__in=value)
        return queryset

    def filter_max_age(self, queryset: QuerySet, name: str, value: int) -> QuerySet:
        cutoff = timezone.now() - timedelta(days=int(value))
        return queryset.filter(last_seen__gte=cutoff)
