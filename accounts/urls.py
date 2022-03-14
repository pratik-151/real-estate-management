from django.urls import path
from . import views
from django.conf.urls import url

urlpatterns = [
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('register', views.register, name='register'),
    path('dashboard',views.dashboard,name='dashboard'),
    path('forgotpassword',views.forgotpassword,name='forgotpassword'),
]