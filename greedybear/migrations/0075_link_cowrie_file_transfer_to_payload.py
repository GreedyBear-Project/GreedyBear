import re

import django.db.models.deletion
from django.db import migrations, models


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def normalize_sha256(value, model_name, object_id):
    normalized = (value or "").strip().lower()
    if not SHA256_PATTERN.fullmatch(normalized):
        raise RuntimeError(f"{model_name} {object_id} has an invalid SHA256: {value!r}")
    return normalized


def normalize_payload_sha256(apps, schema_editor):
    HoneypotPayload = apps.get_model("greedybear", "HoneypotPayload")
    database = schema_editor.connection.alias

    payloads = HoneypotPayload.objects.using(database).order_by("id")
    for payload in payloads.iterator():
        normalized = normalize_sha256(
            payload.sha256,
            "HoneypotPayload",
            payload.pk,
        )
        if payload.sha256 != normalized:
            payload.sha256 = normalized
            payload.save(using=database, update_fields=["sha256"])


def link_transfers_to_payloads(apps, schema_editor):
    CowrieFileTransfer = apps.get_model("greedybear", "CowrieFileTransfer")
    HoneypotPayload = apps.get_model("greedybear", "HoneypotPayload")
    Honeypot = apps.get_model("greedybear", "Honeypot")
    database = schema_editor.connection.alias

    cowrie_honeypot, _ = Honeypot.objects.using(database).get_or_create(
        name="Cowrie",
        defaults={"active": True},
    )

    transfers = (
        CowrieFileTransfer.objects.using(database)
        .select_related("session")
        .order_by("id")
    )

    for transfer in transfers.iterator():
        sha256 = normalize_sha256(
            transfer.shasum,
            "CowrieFileTransfer",
            transfer.pk,
        )

        payload = (HoneypotPayload.objects.using(database).filter(sha256=sha256).first())

        if payload is None:
            payload = HoneypotPayload.objects.using(database).create(sha256=sha256, payload_file=None)

        payload.iocs.add(transfer.session.source_id)
        payload.source_honeypots.add(cowrie_honeypot)

        duplicate = (
            CowrieFileTransfer.objects.using(database)
            .filter(session_id=transfer.session_id, payload_id=payload.pk)
            .exclude(pk=transfer.pk)
            .first()
        )

        if duplicate is not None:
            changed_fields = []

            if transfer.timestamp > duplicate.timestamp:
                duplicate.timestamp = transfer.timestamp
                changed_fields.append("timestamp")

            if not duplicate.url and transfer.url:
                duplicate.url = transfer.url
                changed_fields.append("url")

            if not duplicate.outfile and transfer.outfile:
                duplicate.outfile = transfer.outfile
                changed_fields.append("outfile")

            if changed_fields:
                duplicate.save(using=database, update_fields=changed_fields)

            transfer.delete(using=database)
            continue

        transfer.payload_id = payload.pk
        transfer.save(using=database, update_fields=["payload"])

class Migration(migrations.Migration):
    dependencies = [("greedybear", "0074_rename_tor_exit_reputation")]

    operations = [
        migrations.AddField(
            model_name="cowriefiletransfer",
            name="payload",
            field=models.ForeignKey(
                null=True,
                db_index=False,
                db_constraint=False,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="cowrie_file_transfers",
                to="greedybear.honeypotpayload",
            ),
        ),
        migrations.RunPython(
            normalize_payload_sha256,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name="honeypotpayload",
            name="sha256",
            field=models.CharField(max_length=64, unique=True),
        ),
        migrations.RemoveConstraint(
            model_name="honeypotpayload",
            name="unique_honeypotpayload_sha256_lower",
        ),
        migrations.AddConstraint(
            model_name="honeypotpayload",
            constraint=models.CheckConstraint(
                condition=models.Q(sha256__regex=r"^[0-9a-f]{64}$"),
                name="honeypotpayload_sha256_valid",
            ),
        ),
        migrations.RunPython(
            link_transfers_to_payloads,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
