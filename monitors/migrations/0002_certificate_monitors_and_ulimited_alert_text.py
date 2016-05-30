# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django_pgjson.fields
from django.conf import settings
import django.contrib.postgres.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('monitors', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CertificateMonitor',
            fields=[
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('lookup_interval', models.IntegerField()),
                ('next_lookup', models.DateTimeField()),
                ('last_hosts', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=254), blank=True, null=True, size=None)),
                ('certificate_value', models.TextField(serialize=False, primary_key=True)),
                ('resolutions', django_pgjson.fields.JsonField()),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('tags', models.ManyToManyField(blank=True, to='monitors.IndicatorTag')),
            ],
        ),
        migrations.AlterField(
            model_name='indicatoralert',
            name='indicator',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='indicatoralert',
            name='message',
            field=models.TextField(),
        ),
        migrations.AlterUniqueTogether(
            name='certificatemonitor',
            unique_together=set([('owner', 'certificate_value')]),
        ),
    ]
