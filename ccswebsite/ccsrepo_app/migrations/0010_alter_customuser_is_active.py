# Generated by Django 5.1.1 on 2024-10-14 03:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0009_alter_customuser_is_active_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
    ]
