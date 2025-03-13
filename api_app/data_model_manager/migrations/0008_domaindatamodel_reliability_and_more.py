# Generated by Django 4.2.17 on 2025-02-26 14:06

import django.core.validators
from django.db import migrations, models


def migrate(apps, schema_editor):
    DomainDataModel = apps.get_model("data_model_manager", "DomainDataModel")
    IpDataModel = apps.get_model("data_model_manager", "IpDataModel")
    FileDataModel = apps.get_model("data_model_manager", "FileDataModel")
    for class_ in [DomainDataModel, IpDataModel, FileDataModel]:
        class_.objects.filter(evaluation="clean").update(reliability=4)
        class_.objects.filter(evaluation="suspicious").update(reliability=4)
        class_.objects.filter(evaluation="malicious").update(reliability=8)
        class_.objects.filter(evaluation="trusted").update(reliability=8)


class Migration(migrations.Migration):

    dependencies = [
        ("data_model_manager", "0007_alter_signature_url"),
    ]

    operations = [
        migrations.AddField(
            model_name="domaindatamodel",
            name="reliability",
            field=models.PositiveIntegerField(
                default=5,
                validators=[
                    django.core.validators.MinValueValidator(0),
                    django.core.validators.MaxValueValidator(10),
                ],
            ),
        ),
        migrations.AddField(
            model_name="filedatamodel",
            name="reliability",
            field=models.PositiveIntegerField(
                default=5,
                validators=[
                    django.core.validators.MinValueValidator(0),
                    django.core.validators.MaxValueValidator(10),
                ],
            ),
        ),
        migrations.AddField(
            model_name="ipdatamodel",
            name="reliability",
            field=models.PositiveIntegerField(
                default=5,
                validators=[
                    django.core.validators.MinValueValidator(0),
                    django.core.validators.MaxValueValidator(10),
                ],
            ),
        ),
        migrations.RunPython(migrate, migrations.RunPython.noop),
    ]
