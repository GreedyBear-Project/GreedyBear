from django.db import migrations


def migrate_credential_reuse_tags(apps, schema_editor):
    schema_editor.execute(
        """
        UPDATE greedybear_ioc
        SET high_credential_reuse = TRUE
        WHERE id IN (
            SELECT ioc_id FROM greedybear_tag
            WHERE source = 'credential_reuse'
              AND key = 'behavior'
              AND value = 'high_credential_reuse'
        );
        """
    )
    schema_editor.execute(
        """
        DELETE FROM greedybear_tag
        WHERE source = 'credential_reuse'
          AND key = 'behavior'
          AND value = 'high_credential_reuse';
        """
    )


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0068_ioc_high_credential_reuse"),
    ]

    operations = [
        migrations.RunPython(migrate_credential_reuse_tags, reverse_code=migrations.RunPython.noop),
    ]
