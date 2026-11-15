from django.db import migrations, models

OLD_LABEL = "tor exit node"
NEW_LABEL = "tor exit"


def rename_label(old, new):
    def rename(apps, schema_editor):
        """Use the same Tor exit node label as T-Pot (listbot)."""
        apps.get_model("greedybear", "IOC").objects.filter(ip_reputation=old).update(ip_reputation=new)
        apps.get_model("greedybear", "TorExitNode").objects.filter(reason=old).update(reason=new)

    return rename


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0073_alter_firehollist_ip_address_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="torexitnode",
            name="reason",
            field=models.CharField(blank=True, default=NEW_LABEL, max_length=64),
        ),
        migrations.RunPython(rename_label(OLD_LABEL, NEW_LABEL), reverse_code=rename_label(NEW_LABEL, OLD_LABEL)),
    ]
