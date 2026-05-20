from django.db import migrations, models


def deduplicate_ioc_identity(apps, schema_editor):
    IOC = apps.get_model("greedybear", "IOC")

    duplicate_ids = []
    seen_pairs = set()

    queryset = (
        IOC.objects.order_by("name", "type", "-attack_count", "-id")
        .values_list("id", "name", "type")
        .iterator(chunk_size=1000)
    )

    for ioc_id, name, ioc_type in queryset:
        key = (name, ioc_type)
        if key in seen_pairs:
            duplicate_ids.append(ioc_id)
            continue
        seen_pairs.add(key)

    batch_size = 1000
    for start in range(0, len(duplicate_ids), batch_size):
        IOC.objects.filter(id__in=duplicate_ids[start : start + batch_size]).delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("greedybear", "0052_ioc_attacker_country_code_idx"),
    ]

    operations = [
        migrations.RunPython(deduplicate_ioc_identity, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="ioc",
            constraint=models.UniqueConstraint(fields=("name", "type"), name="unique_ioc_identity"),
        ),
    ]
