# Generated by Django 5.1.2 on 2024-10-29 14:01

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0007_manuscript_feedback'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='manuscript',
            name='keywords',
        ),
        migrations.DeleteModel(
            name='Keyword',
        ),
    ]
