# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings
import django.contrib.postgres.fields


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='DomainMonitor',
            fields=[
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('lookup_interval', models.IntegerField()),
                ('next_lookup', models.DateTimeField()),
                ('last_hosts', django.contrib.postgres.fields.ArrayField(size=None, null=True, base_field=models.CharField(max_length=254), blank=True)),
                ('domain_name', models.CharField(primary_key=True, serialize=False, max_length=253)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='IndicatorAlert',
            fields=[
                ('id', models.AutoField(primary_key=True, verbose_name='ID', serialize=False, auto_created=True)),
                ('indicator', models.CharField(max_length=253)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('message', models.CharField(max_length=100)),
                ('recipient', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='IndicatorTag',
            fields=[
                ('id', models.AutoField(primary_key=True, verbose_name='ID', serialize=False, auto_created=True)),
                ('tag', models.CharField(max_length=40)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='IpMonitor',
            fields=[
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True)),
                ('lookup_interval', models.IntegerField()),
                ('next_lookup', models.DateTimeField()),
                ('last_hosts', django.contrib.postgres.fields.ArrayField(size=None, null=True, base_field=models.CharField(max_length=254), blank=True)),
                ('ip_address', models.GenericIPAddressField(primary_key=True, unpack_ipv4=True, serialize=False)),
                ('owner', models.ForeignKey(to=settings.AUTH_USER_MODEL)),
                ('tags', models.ManyToManyField(to='monitors.IndicatorTag', blank=True)),
            ],
        ),
        migrations.AddField(
            model_name='domainmonitor',
            name='tags',
            field=models.ManyToManyField(to='monitors.IndicatorTag', blank=True),
        ),
        migrations.AlterUniqueTogether(
            name='ipmonitor',
            unique_together=set([('owner', 'ip_address')]),
        ),
        migrations.AlterUniqueTogether(
            name='indicatortag',
            unique_together=set([('tag', 'owner')]),
        ),
        migrations.AlterUniqueTogether(
            name='domainmonitor',
            unique_together=set([('owner', 'domain_name')]),
        ),
    ]
