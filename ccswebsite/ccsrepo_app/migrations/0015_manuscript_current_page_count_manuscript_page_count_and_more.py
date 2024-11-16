# Generated by Django 5.1.2 on 2024-11-12 20:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ccsrepo_app', '0014_adviserstudentrelationship_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='manuscript',
            name='current_page_count',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='manuscript',
            name='page_count',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='manuscript',
            name='remaining_page',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]