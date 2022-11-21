# Generated by Django 3.2.16 on 2022-11-21 07:21

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('username', models.CharField(max_length=200)),
                ('first_name', models.CharField(max_length=300)),
                ('last_name', models.CharField(max_length=300)),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('password', models.CharField(max_length=100)),
                ('profile_pic', models.ImageField(upload_to='Computerizer/static/Oauth/media')),
                ('sub_to_newsletter', models.BooleanField(default=True)),
                ('own_pc', models.BooleanField(default=False)),
                ('active', models.BooleanField(default=True, null=True)),
                ('staff', models.BooleanField(default=False, null=True)),
                ('admin', models.BooleanField(default=False, null=True)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
