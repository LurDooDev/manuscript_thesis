# Generated by Django 5.1.2 on 2024-11-07 20:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0003_remove_pageocrdata_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='adviserstudentrelationship',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
    ]
