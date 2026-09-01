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
        migrations.AlterField(
            model_name='ioc',
            name='name',
            field=models.CharField(max_length=256, unique=True),
        ),
        # Explicit index is duplicate now
        # because unique=True implies the creation of an index
        migrations.RemoveIndex(
            model_name='ioc',
            name='greedybear__name_b54897_idx',
        ),
    ]
