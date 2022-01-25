# Generated by Django 3.2.5 on 2021-07-11 19:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('playground', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Task',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('completed', models.BooleanField(blank=True, default=False, null=True)),
            ],
        ),
    ]