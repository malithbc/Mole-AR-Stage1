# Generated by Django 3.2.5 on 2021-07-28 06:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0013_image_object_3d'),
    ]

    operations = [
        migrations.AlterField(
            model_name='image',
            name='object_3D',
            field=models.FileField(upload_to='Object3D/'),
        ),
    ]
