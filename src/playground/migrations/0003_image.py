# Generated by Django 3.2.5 on 2021-07-12 00:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0002_task'),
    ]

    operations = [
        migrations.CreateModel(
            name='Image',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('image', models.ImageField(upload_to='images/')),
            ],
        ),
    ]
