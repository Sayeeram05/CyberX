from django.urls import path
from . import views

app_name = 'NetworkIDS'

urlpatterns = [
    path('',                              views.index,          name='index'),
    path('start/',                        views.start_analysis, name='start_analysis'),
    path('status/<uuid:session_id>/',     views.get_status,     name='get_status'),
    path('stop/<uuid:session_id>/',       views.stop_capture,   name='stop_capture'),
    path('results/<uuid:session_id>/',    views.get_results,    name='get_results'),
    path('api/analyze/',                  views.api_analyze,    name='api_analyze'),
]
