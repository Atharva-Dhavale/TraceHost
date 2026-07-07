from django.urls import path
from . import views

urlpatterns = [
    path('health',             views.health_check,           name='health_check'),
    path('analyze',            views.analyze_domain,          name='analyze_domain'),
    path('analyze/invalidate', views.invalidate_domain_cache, name='invalidate_domain_cache'),
    path('suspicious',         views.suspicious_view,         name='suspicious_view'),
    path('dashboard',          views.get_dashboard_data,      name='dashboard_data'),
    path('suspicious_domains', views.suspicious_domains_list, name='suspicious_domains_list'),
    path('flag_domain',        views.flag_domain,             name='flag_domain'),
    path('scan_history',       views.scan_history,            name='scan_history'),
]
