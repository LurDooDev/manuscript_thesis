from django.shortcuts import render
from django.views import View
# Create your views here.

#
class UsernameValidation(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')
    
class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')
