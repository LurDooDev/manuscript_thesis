from .views import RegistrationView, LoginView, UsernameValidationView
from django.urls import path
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('register', RegistrationView.as_view(), name='register'),
    path("validate-username", csrf_exempt(UsernameValidationView.as_view()),name="validate-username"),
    path('login', LoginView.as_view(), name='login')

]
