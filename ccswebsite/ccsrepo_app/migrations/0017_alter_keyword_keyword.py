# Generated by Django 5.1.2 on 2024-11-15 10:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0016_keyword'),
    ]

    operations = [
        migrations.AlterField(
            model_name='keyword',
            name='keyword',
            field=models.CharField(max_length=255),
        ),
    ]