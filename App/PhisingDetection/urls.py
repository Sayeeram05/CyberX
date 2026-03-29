"""
URL configuration for PhishingDetection app.
"""
from django.urls import path
from . import views

app_name = 'phishingdetection'

urlpatterns = [
    path('', views.index, name='index'),
    path('api/analyze/', views.api_analyze, name='api_analyze'),
]
