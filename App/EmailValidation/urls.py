from django.urls import path
from . import views

app_name = 'emailvalidation'

urlpatterns = [
    path('', views.email_validation_view, name='index'),
    path('api/validate/', views.validate_email_api, name='validate_api'),
]