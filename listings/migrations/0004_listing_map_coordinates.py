# Generated by Django 3.2.4 on 2022-03-16 10:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('listings', '0003_auto_20220310_0947'),
    ]

    operations = [
        migrations.AddField(
            model_name='listing',
            name='map_coordinates',
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
