# Generated by Django 5.1.2 on 2024-10-20 23:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0005_alter_manuscript_keywords'),
    ]

    operations = [
        migrations.AlterField(
            model_name='manuscript',
            name='publication_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]