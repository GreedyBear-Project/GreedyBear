# Generated migration for DashboardConfig model

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0058_eventstatus_rawevent_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="DashboardConfig",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "layout",
                    models.JSONField(
                        help_text=(
                            "Serialised dashboard layout: "
                            "{widgetConfigs: [...], layouts: {...}}"
                        )
                    ),
                ),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        help_text="The superuser who last saved this configuration.",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="dashboard_configs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Dashboard Configuration",
                "verbose_name_plural": "Dashboard Configurations",
            },
        ),
    ]
