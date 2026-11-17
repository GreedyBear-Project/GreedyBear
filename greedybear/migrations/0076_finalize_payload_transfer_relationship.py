import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("greedybear", "0075_link_cowrie_file_transfer_to_payload"),
    ]

    operations = [
        migrations.AlterField(
            model_name="cowriefiletransfer",
            name="payload",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="cowrie_file_transfers",
                to="greedybear.honeypotpayload",
            ),
        ),
        migrations.RemoveConstraint(
            model_name="cowriefiletransfer",
            name="unique_download_per_session",
        ),
        migrations.AddConstraint(
            model_name="cowriefiletransfer",
            constraint=models.UniqueConstraint(
                fields=("payload", "session"),
                name="unique_payload_transfer_per_session",
            ),
        ),
        migrations.RemoveIndex(
            model_name="cowriefiletransfer",
            name="greedybear__shasum_083f18_idx",
        ),
        migrations.RemoveField(
            model_name="cowriefiletransfer",
            name="shasum",
        ),
        migrations.RemoveField(
            model_name="honeypotpayload",
            name="cowrie_sessions",
        ),
    ]