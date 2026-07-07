from django.urls import path
from . import views

urlpatterns = [
    path('scan',       views.attack_surface_scan,            name='attack_surface_scan'),
    path('invalidate', views.invalidate_attack_surface_cache, name='invalidate_attack_surface_cache'),
]
