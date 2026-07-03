from django.contrib import admin
from django.urls import path
from checker.views import analyze_domain, suspicious_view, get_dashboard_data, suspicious_domains_list, flag_domain, health_check

urlpatterns = [
    path('admin/', admin.site.urls),

    # API endpoints
    path('api/analyze', analyze_domain, name='check_domain'),
    path('api/suspicious', suspicious_view, name='suspicious_view'),
    path('api/dashboard', get_dashboard_data, name='dashboard_data'),
    path('api/suspicious_domains', suspicious_domains_list, name='suspicious_domains_list'),
    path('api/flag_domain', flag_domain, name='flag_domain'),
    path('health', health_check, name='health_check'),
]

# Add custom 404 and 500 handlers
handler404 = 'project.views.custom_404'
handler500 = 'project.views.custom_500' 