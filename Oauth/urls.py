from django.urls import path
from rest_framework.authtoken import views
from django.views.decorators.csrf import csrf_exempt
from .views import *
urlpatterns = [
    path('members/create-user',Register.as_view(),name='post_view'),
    path('members/user',GetUserInfo.as_view(),name='get_view'),
    #path('members/update-info',UpdateUserInfo.as_view(),name='update_user_info'), # have some bugs!
    path('members/all-users',GetAllUsers.as_view(),name='all_users'),
    path('members/delete-user',DeleteUserInfo.as_view(),name='delete_user'),
    path('members/login',Login.as_view(),name='login'),
    path('members/logout',Logout.as_view(),name='logout'),
    path('activate/<uidb64>/<token>', activate, name='activate'),
    path('api-token-auth', views.obtain_auth_token,name='auth_token'),
]