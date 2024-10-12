from .views import RegistrationView, LoginView
from django.urls import path
from . import views
# from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('register', RegistrationView.as_view(), name='register'),
    # path("validate-username", csrf_exempt(UsernameValidationView.as_view()),name="validate-username"),
    path('login', LoginView.as_view(), name='login'),
    path('', views.index, name='records'),
    path('add-program', views.add_program, name='add-program'),

]