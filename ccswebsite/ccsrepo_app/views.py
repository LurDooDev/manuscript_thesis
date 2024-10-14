from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import CustomUser, Program, Category, Type, Batch, AdviserStudentRelationship
from django.contrib.auth.decorators import login_required

#dashboard
@login_required(login_url='login')
def dashboard_view(request):
    return render(request, 'ccsrepo_app/dashboard.html')

#logout
def logout_view(request):
    logout(request)
    return redirect('home')

#Logging In
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_student or user.is_adviser or user.is_admin:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.warning(request, "Your account is not registered as a student. Please contact your adviser.")
                login(request, user)
                return redirect('adviser_request') 
        else:
            messages.error(request, "Invalid username or password. Please try again.")
            return redirect('login')
    return render(request, 'ccsrepo_app/login.html')

#----------------Student and Adviser ------------------------/

#View of Request to Adviser
def success_request_view(request):
    return render(request, 'ccsrepo_app/adviser_request_success.html')

#verify to adviser view
def request_adviser_view(request):
    if request.method == 'POST':
        adviser_email = request.POST.get('email')
        student = request.user

        try:
            # Find the adviser email, to make sure its an adviser
            adviser = CustomUser.objects.get(email=adviser_email, is_adviser=True)

            # Check to prevent duplicates
            if AdviserStudentRelationship.objects.filter(adviser=adviser, student=student).exists():
                messages.warning(request, "You have already sent a request to this adviser.")
            else:
                # adviser-student relationship
                AdviserStudentRelationship.objects.create(adviser=adviser, student=student)
                messages.success(request, "Your request has been sent to your adviser.")
                return redirect('adviser_request_success')

        except CustomUser.DoesNotExist:
            messages.error(request, "No adviser found with this email or they are not an adviser.")
        except Exception as e:
            messages.error(request, "An error occurred. Please try again.")

    return render(request, 'ccsrepo_app/adviser_request.html')

#Approve Student View for Adviser
def approve_student_view(request):
    if not request.user.is_adviser:
        messages.error(request, "You are not authorized to approve students.")
        return redirect('dashboard')
    
    relationships = AdviserStudentRelationship.objects.filter(adviser=request.user)

    if request.method == 'POST':
        student_id = request.POST.get('student_id')
        try:
            student_relationship = get_object_or_404(AdviserStudentRelationship, id=student_id, adviser=request.user)
            student = student_relationship.student
            student.is_student = True
            student.save()

            messages.success(request, f"{student.username} has been approved as a student.")
            return redirect('adviser_approve_student')

        except Exception as e:
            messages.error(request, "An error occurred. Please try again.")

    return render(request, 'ccsrepo_app/adviser_approve_student.html', {'relationships': relationships})
#----------------End Student and Adviser ------------------------/

#Register Student
def StudentRegister(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        program_id = request.POST.get('program')

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
            is_student=False,
            program_id=program_id
        )
        user.set_password(password1)
        user.save()
        
        messages.success(request, "Registration successful!")
        return redirect('login')
    
    programs = Program.objects.all()
    return render(request, 'ccsrepo_app/register.html', {'programs': programs})
#----------------Admin Managing ------------------------/

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

#Category
def manage_category(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        
        if Category.objects.filter(name=name).exists():
            messages.error(request, "A category with this name already exists.")
            return redirect('manage_category')
        
        Category.objects.create(name=name)
        messages.success(request, "Category added successfully.")
        return redirect('manage_category')

    category = Category.objects.all() 
    return render(request, 'ccsrepo_app/manage_category.html', {'category': category})

#Batch
def manage_batch(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        
        if Batch.objects.filter(name=name).exists():
            messages.error(request, "A Batch with this name already exists.")
            return redirect('manage_batch')
        
        Batch.objects.create(name=name)
        messages.success(request, "Batch added successfully.")
        return redirect('manage_batch')

    batch = Batch.objects.all() 
    return render(request, 'ccsrepo_app/manage_batch.html', {'batch': batch})

#Type
def manage_type(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        
        if Type.objects.filter(name=name).exists():
            messages.error(request, "A Type with this name already exists.")
            return redirect('manage_type')
        
        Type.objects.create(name=name)
        messages.success(request, "Type added successfully.")
        return redirect('manage_type')

    type = Type.objects.all() 
    return render(request, 'ccsrepo_app/manage_type.html', {'type': type})

#Manage Users
def ManageAdviser(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        program_id = request.POST.get('program')
        # Validation
        if password1 != password2:
            messages.error(request, "Passwords do not match.")
            return redirect('manage_users')
        
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect('manage_users')

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('manage_users')
        
        user = CustomUser(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            is_adviser=True,
            program_id=program_id
        )
        user.set_password(password1)
        user.save()

        messages.success(request, "Registration successful! You can now log in.")
        return redirect('manage_users')

    advisers = CustomUser.objects.filter(is_adviser=True).values('first_name', 'last_name', 'email')
    return render(request, 'ccsrepo_app/manage_users.html', {'advisers': advisers})
#----------------End Admin Managing ------------------------/
