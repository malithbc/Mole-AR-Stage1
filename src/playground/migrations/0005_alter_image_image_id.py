# Generated by Django 3.2.5 on 2021-07-12 20:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0004_auto_20210712_1321'),
    ]

    operations = [
        migrations.AlterField(
            model_name='image',
            name='image_id',
            field=models.CharField(max_length=100),
        ),
    ]
