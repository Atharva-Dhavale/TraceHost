from django.urls import path
from . import views
from django.views.decorators.cache import cache_page

urlpatterns = [
    # Main API endpoints that match frontend expectations
    path('analyze', views.analyze_domain, name='check_domain'),  # Frontend expects /api/analyze
    path('suspicious', views.suspicious_view, name='suspicious_view'),  # Frontend expects /api/suspicious
    path('dashboard', cache_page(60 * 5)(views.get_dashboard_data), name='dashboard-data'),  # Frontend expects /api/dashboard
    path('suspicious_domains', views.suspicious_domains_list, name='suspicious_domains_list'),  # Frontend expects /api/suspicious_domains
    path('flag_domain', views.flag_domain, name='flag_domain'),  # Add new endpoint for flagging domains
    
    # Additional routes with trailing slashes for flexibility
    path('domain-check/', views.analyze_domain, name='domain_check'),
    path('suspicious/', views.suspicious_view, name='suspicious_view_alt'),
    path('dashboard/', views.get_dashboard_data, name='dashboard_data_alt'),
    path('suspicious-domains/', views.suspicious_domains_list, name='suspicious_domains_list_alt'),
    path('flag-domain/', views.flag_domain, name='flag_domain_alt'),
    
    # Keep the old paths for backward compatibility
    path('check_domain/', views.analyze_domain, name='check_domain_old'),
    path('api/analyze_domain/', views.analyze_domain, name='analyze_domain_old'),
    path('api/check_domain/', views.analyze_domain, name='check_domain_api_old'),
    path('api/get_dashboard_data/', cache_page(60 * 5)(views.get_dashboard_data), name='dashboard-data-old'),
]
