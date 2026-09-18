"""
Data migration to move Tanner's attack_type tags from the Tag model
into the new IOC.http_attack_types ArrayField.
"""

from django.db import migrations


def migrate_tanner_attack_types(apps, schema_editor):
    schema_editor.execute("""
        UPDATE greedybear_ioc
        SET http_attack_types = sub.types
        FROM (
            SELECT ioc_id, array_agg(DISTINCT value ORDER BY value) AS types
            FROM greedybear_tag
            WHERE source = 'tanner' AND key = 'attack_type'
            GROUP BY ioc_id
        ) AS sub
        WHERE greedybear_ioc.id = sub.ioc_id;
    """)

    schema_editor.execute("""
        DELETE FROM greedybear_tag
        WHERE source = 'tanner' AND key = 'attack_type';
    """)


class Migration(migrations.Migration):

    dependencies = [
        ("greedybear", "0063_ioc_http_attack_types"),
    ]

    operations = [
        migrations.RunPython(migrate_tanner_attack_types, reverse_code=migrations.RunPython.noop),
    ]