# Generated by Django 3.2.5 on 2021-07-29 02:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0016_alter_image_object_3d'),
    ]

    operations = [
        migrations.AddField(
            model_name='image',
            name='mtl',
            field=models.FileField(default='Object3D/mtl1', upload_to='Object3D/3358df95-6bc9-4bbf-99a4-0a79cb29098a/'),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='image',
            name='object_3D',
            field=models.FileField(upload_to='Object3D/3358df95-6bc9-4bbf-99a4-0a79cb29098a/'),
        ),
    ]
