from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import CustomUser, Program
from django.contrib.auth.decorators import login_required

#dashboard
@login_required
def dashboard_view(request):
    return render(request, 'ccsrepo_app/dashboard.html')

def logout_view(request):
    logout(request)
    return redirect('login')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login successful! Welcome back.")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid username or password. Please try again.")
            return redirect('login')

    return render(request, 'ccsrepo_app/login.html')


#Program
def manage_program(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        abbreviation = request.POST.get('abbreviation')
        
        if Program.objects.filter(name=name).exists():
            messages.error(request, "A program with this name already exists.")
            return redirect('manage_program')
        
        Program.objects.create(name=name, abbreviation=abbreviation)
        messages.success(request, "Program added successfully.")
        return redirect('manage_program')

    programs = Program.objects.all() 
    return render(request, 'ccsrepo_app/manage_program.html', {'programs': programs})


#Register Student and Viewing page
def StudentRegister(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        #validation
        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('register')
        
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect('register')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('register')

        user = CustomUser(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            is_student=True
        )
        user.set_password(password1)
        user.save()
        
        messages.success(request, "Registration successful! You can now log in.")
        return redirect('login')

    return render(request, 'ccsrepo_app/register.html')
