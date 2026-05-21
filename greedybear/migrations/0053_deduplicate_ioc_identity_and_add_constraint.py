from django.db import migrations, models
from django.db.models import Subquery


def deduplicate_ioc_identity(apps, schema_editor):
    IOC = apps.get_model("greedybear", "IOC")

    keepers = (
        IOC.objects.order_by("name", "-attack_count", "-id")
        .distinct("name")
        .values("id")
    )

    IOC.objects.exclude(id__in=Subquery(keepers)).delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("greedybear", "0052_ioc_attacker_country_code_idx"),
    ]

    operations = [
        migrations.RunPython(deduplicate_ioc_identity, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="ioc",
            constraint=models.UniqueConstraint(fields=("name",), name="unique_ioc_name"),
        ),
    ]
