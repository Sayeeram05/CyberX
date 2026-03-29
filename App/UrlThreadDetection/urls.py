from django.urls import path
from . import views

app_name = 'urlthreatdetection'

urlpatterns = [
    path('', views.url_threat_detection_view, name='index'),
    path('analyze/', views.analyze_url_api, name='analyze_url'),
]