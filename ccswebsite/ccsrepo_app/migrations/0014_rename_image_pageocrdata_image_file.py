# Generated by Django 5.1.2 on 2024-10-29 19:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0013_alter_pageocrdata_image'),
    ]

    operations = [
        migrations.RenameField(
            model_name='pageocrdata',
            old_name='image',
            new_name='image_file',
        ),
    ]