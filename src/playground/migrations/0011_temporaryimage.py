# Generated by Django 3.2.5 on 2021-07-13 05:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0010_alter_extractfeature_descriptor'),
    ]

    operations = [
        migrations.CreateModel(
            name='TemporaryImage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image_id', models.CharField(max_length=100)),
                ('image', models.ImageField(upload_to='temporary_images/')),
            ],
        ),
    ]
