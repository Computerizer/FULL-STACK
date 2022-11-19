from django.urls import path
from . import views

urlpatterns = [
    path('subscribe', views.SubscribeMailchimp.as_view(), name='subscribe_mailchimp-api')
]