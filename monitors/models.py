from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import ArrayField
from django_pgjson.fields import JsonField


class IndicatorLookupBase(models.Model):
    """
    Base model for indicator lookups
    """
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True)
    lookup_interval = models.IntegerField()
    next_lookup = models.DateTimeField()
    last_hosts = ArrayField(models.CharField(max_length=254), blank=True, null=True)
    tags = models.ManyToManyField('IndicatorTag', blank=True)

    class Meta:
        abstract = True


class DomainMonitor(IndicatorLookupBase):
    domain_name = models.CharField(max_length=253, primary_key=True)

    class Meta:
        unique_together = (('owner', 'domain_name'),)


class IpMonitor(IndicatorLookupBase):
    ip_address = models.GenericIPAddressField(unpack_ipv4=True, primary_key=True)

    class Meta:
        unique_together = (('owner', 'ip_address'),)


class CertificateMonitor(IndicatorLookupBase):
    """
    A lookup monitor for certificate indicators.

    This class extends IndicatorLookupBase, adding the field 'certificate_value' for the indicator value as a primary
    key. As with all indicator lookups, the combination of indicator value and owner must be unique.
    """

    certificate_value = models.TextField(primary_key=True)
    """The certificate fragment to be monitored"""

    resolutions = JsonField()
    """
    The full resolutions.  Here is the basic structure of this field:

    { <ip>: { "geo_location": <location>, "country": <code>, "domains": [ <domain>, ...] } }
    """

    class Meta:
        """
        A metaclass for Certificate Monitor that specifies that the combination of 'owner' (the person submitting the
        monitor) and 'certificate_value' (the indicator value) must be unique.
        """
        unique_together = (('owner', 'certificate_value'),)


class IndicatorAlert(models.Model):
    """
    Base model for indicator alerts
    """
    indicator = models.TextField()
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    message = models.TextField()


class IndicatorTag(models.Model):
    tag = models.CharField(max_length=40)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)

    def __unicode__(self):
        return self.tag

    def __str__(self):
        return self.tag

    class Meta:
        unique_together = (('tag', 'owner'),)
