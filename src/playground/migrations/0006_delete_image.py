# Generated by Django 3.2.5 on 2021-07-12 20:26

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0005_alter_image_image_id'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Image',
        ),
    ]
