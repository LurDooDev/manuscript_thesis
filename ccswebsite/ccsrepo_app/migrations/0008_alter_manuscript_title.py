# Generated by Django 5.1.2 on 2024-11-08 13:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0007_alter_manuscript_title'),
    ]

    operations = [
        migrations.AlterField(
            model_name='manuscript',
            name='title',
            field=models.TextField(max_length=255, null=True),
        ),
    ]