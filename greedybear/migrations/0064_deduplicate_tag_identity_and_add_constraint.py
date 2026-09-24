from django.db import migrations, models
from django.db.models import Subquery


def deduplicate_tag_identity(apps, schema_editor):
    Tag = apps.get_model("greedybear", "Tag")

    keepers = Tag.objects.order_by("ioc_id", "source", "key", "value", "added", "id").distinct("ioc_id", "source", "key", "value").values("id")

    Tag.objects.exclude(id__in=Subquery(keepers)).delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("greedybear", "0063_eventstatus_started_at"),
    ]

    operations = [
        migrations.RunPython(deduplicate_tag_identity, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="tag",
            constraint=models.UniqueConstraint(fields=["ioc", "source", "key", "value"], name="unique_tag_identity"),
        ),
    ]
