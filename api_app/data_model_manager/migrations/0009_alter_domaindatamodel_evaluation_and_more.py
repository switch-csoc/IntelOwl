# Generated by Django 4.2.17 on 2025-02-28 11:18

from django.db import migrations

import api_app.data_model_manager.fields


def migrate(apps, schema_editor):
    DomainDataModel = apps.get_model("data_model_manager", "DomainDataModel")
    IpDataModel = apps.get_model("data_model_manager", "IpDataModel")
    FileDataModel = apps.get_model("data_model_manager", "FileDataModel")
    for class_ in [DomainDataModel, IpDataModel, FileDataModel]:
        class_.objects.filter(evaluation="clean").update(evaluation="trusted")
        class_.objects.filter(evaluation="suspicious").update(evaluation="malicious")


class Migration(migrations.Migration):

    dependencies = [
        ("data_model_manager", "0008_domaindatamodel_reliability_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="domaindatamodel",
            name="evaluation",
            field=api_app.data_model_manager.fields.LowercaseCharField(
                blank=True,
                choices=[("trusted", "Trusted"), ("malicious", "Malicious")],
                default=None,
                max_length=100,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="filedatamodel",
            name="evaluation",
            field=api_app.data_model_manager.fields.LowercaseCharField(
                blank=True,
                choices=[("trusted", "Trusted"), ("malicious", "Malicious")],
                default=None,
                max_length=100,
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="ipdatamodel",
            name="evaluation",
            field=api_app.data_model_manager.fields.LowercaseCharField(
                blank=True,
                choices=[("trusted", "Trusted"), ("malicious", "Malicious")],
                default=None,
                max_length=100,
                null=True,
            ),
        ),
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
