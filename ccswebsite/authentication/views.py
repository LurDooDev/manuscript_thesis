from django.shortcuts import render
from django.contrib.auth.models import User
from django.views import View
import json
from django.http import JsonResponse
# Create your views here.

#
class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']

        if not str(username).isalnum():
            return JsonResponse({'username_error':'username should only containt alphaneumeric'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error':'username already exist'}, status=409)
        return JsonResponse({'username_valid': True})
        


class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')
    
class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')
