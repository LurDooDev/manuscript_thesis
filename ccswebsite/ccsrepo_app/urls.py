from django.urls import path
from .views import StudentRegister, manage_program
from . import views

urlpatterns = [
    path('', views.login_view, name='home'), 
    path('login/', views.login_view, name='login'),
    path('register/', StudentRegister, name='register'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('manage-program/', manage_program, name='manage_program'),
    path('logout/', views.logout_view, name='logout'),
]