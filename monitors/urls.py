from django.conf.urls import patterns, url

from .views import MonitorDashboard
from .views import AddIndicator, AddCertificate, DeleteIndicator
from .views import CertificateList, DomainList, IpList, AlertList
from .views import UntagIndicator, TagIndicator
from .views import export_indicators
from .views import AddTag, DeleteTags


urlpatterns = patterns('',
                       url(r'^$', MonitorDashboard.as_view(), name='monitor_dashboard'),
                       url(r'^add_indicators', AddIndicator.as_view(), name='add_indicators'),
                       url(r'^add_certificate', AddCertificate.as_view(), name='add_certificate'),
                       url(r'^delete_indicators', DeleteIndicator.as_view(), name='delete_indicators'),
                       url(r'^export_indicators', export_indicators, name='export_indicators'),
                       url(r'^tag_indicators', TagIndicator.as_view(), name='tag_indicators'),
                       url(r'^untag_indicators', UntagIndicator.as_view(), name='untag_indicators'),
                       url(r'^view_alerts', AlertList.as_view(), name='view_alerts'),
                       url(r'^view_certificates', CertificateList.as_view(), name='view_certificates'),
                       url(r'^view_domains', DomainList.as_view(), name='view_domains'),
                       url(r'^view_ips', IpList.as_view(), name='view_ips'),
                       url(r'^create_tag', AddTag.as_view(), name='create_tag'),
                       url(r'^delete_tags', DeleteTags.as_view(), name='delete_tags')
                       )
