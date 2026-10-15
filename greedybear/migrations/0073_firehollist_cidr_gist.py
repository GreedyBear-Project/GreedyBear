from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0072_remove_ioc_firehol_categories"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            CREATE INDEX firehollist_cidr_gist
            ON greedybear_firehollist
            USING gist ((ip_address::inet) inet_ops)
            WHERE ip_address LIKE '%/%'
            """,
            reverse_sql="DROP INDEX firehollist_cidr_gist",
        ),
    ]