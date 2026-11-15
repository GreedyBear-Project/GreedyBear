from django.db import migrations

OLD_SOURCE = "firehol"
NEW_SOURCE = "spamhaus_drop"


def move_spamhaus_tags(old, new):
    def move(apps, schema_editor):
        """Give Spamhaus DROP tags their own source instead of the FireHol one."""
        apps.get_model("greedybear", "Tag").objects.filter(source=old, key="blocklist", value="spamhaus_drop").update(source=new)

    return move


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0074_rename_tor_exit_reputation"),
    ]

    operations = [
        migrations.RunPython(move_spamhaus_tags(OLD_SOURCE, NEW_SOURCE), reverse_code=move_spamhaus_tags(NEW_SOURCE, OLD_SOURCE)),
    ]
