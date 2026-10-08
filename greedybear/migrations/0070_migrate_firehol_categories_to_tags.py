from django.db import migrations


def migrate_firehol_categories(apps, schema_editor):
    """Copy each entry of IOC.firehol_categories into a blocklist tag."""
    schema_editor.execute(
        """
        INSERT INTO greedybear_tag (ioc_id, "key", value, source, added)
        SELECT ioc.id, 'blocklist', category, 'firehol', ioc.last_seen
        FROM greedybear_ioc ioc, unnest(ioc.firehol_categories) AS category
        ON CONFLICT DO NOTHING
        """
    )


def noop(apps, schema_editor):
    """No reverse. The source column still holds the data at this point."""


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0069_migrate_credential_reuse_tags"),
    ]

    operations = [
        migrations.RunPython(migrate_firehol_categories, reverse_code=noop),
    ]
