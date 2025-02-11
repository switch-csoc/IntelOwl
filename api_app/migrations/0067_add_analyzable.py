# Generated by Django 4.2.17 on 2025-01-22 08:59

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("api_app", "0066_remove_lastelasticreportupdate_singleton_and_more"),
        ("analyzables_manager", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="job",
            name="analyzable",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="jobs",
                to="analyzables_manager.analyzable",
            ),
        ),
    ]
