from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.utils import timezone
import os
from django.db.models import Q
import pytesseract
from pdf2image import convert_from_path
from .models import CustomUser, Program, Category, ManuscriptType, Batch, AdviserStudentRelationship, Manuscript, Keyword
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator


#----------------Search System ------------------------/
def manuscript_search_page(request):
    search_query = request.GET.get('search', '')
    selected_program = request.GET.get('program', 'All')  # Change here
    selected_category = request.GET.get('category', 'All')
    selected_batch = request.GET.get('batch', 'All')

    manuscripts = Manuscript.objects.all()

    # Filter based on search query
    if search_query:
        manuscripts = manuscripts.filter(
            Q(title__icontains=search_query) |
            Q(abstracts__icontains=search_query) |
            Q(keywords__word__icontains=search_query)  # Assuming you have a ManyToMany relation with Keyword model
        ).distinct()

    # Filter based on selected program
    if selected_program != 'All':
        manuscripts = manuscripts.filter(program=selected_program)

    # Filter based on selected category
    if selected_category != 'All':
        manuscripts = manuscripts.filter(category=selected_category)

    # Filter based on selected batch
    if selected_batch != 'All':
        manuscripts = manuscripts.filter(batch=selected_batch)

    manuscripts = manuscripts.order_by('-publication_date')  # Example order

    # Pagination (example with 10 manuscripts per page)
    paginator = Paginator(manuscripts, 10)
    page_number = request.GET.get('page')
    manuscripts = paginator.get_page(page_number)

    # Retrieve distinct values for dropdowns
    programs = Manuscript.objects.values_list('program', flat=True).distinct()
    categories = Manuscript.objects.values_list('category', flat=True).distinct()
    batches = Manuscript.objects.values_list('batch', flat=True).distinct()

    return render(request, 'ccsrepo_app/manuscript_search_page.html', {
        'manuscripts': manuscripts,
        'search_query': search_query,
        'selected_program': selected_program,
        'selected_category': selected_category,
        'selected_batch': selected_batch,
        'programs': programs,
        'categories': categories,
        'batches': batches,
    })

#----------------End Search ------------------------/


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
            # Redirect students to the search page
            if user.is_student:
                login(request, user)
                return redirect('manuscript_search_page')  # Redirect to search page for students

            # Redirect advisers to the adviser approval page
            elif user.is_adviser:
                login(request, user)
                return redirect('adviser_approve_student')  # Redirect to adviser approve student page

            # Redirect admins to the manage users page
            elif user.is_admin:
                login(request, user)
                return redirect('manage_users')

            else:
                messages.warning(request, "Your account is not registered as a student. Please contact your adviser.")
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
        
        if ManuscriptType.objects.filter(name=name).exists():
            messages.error(request, "A Type with this name already exists.")
            return redirect('manage_type')
        
        ManuscriptType.objects.create(name=name)
        messages.success(request, "Type added successfully.")
        return redirect('manage_type')

    type = ManuscriptType.objects.all() 
    return render(request, 'ccsrepo_app/manage_type.html', {'type': type})

#Register Advisers And Manage
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
    programs = Program.objects.all()
    advisers = CustomUser.objects.filter(is_adviser=True).values('first_name', 'last_name', 'email')
    return render(request, 'ccsrepo_app/manage_users.html', {'advisers': advisers , 'programs': programs})
#----------------End Admin Managing ------------------------/

#----------------Manuscript System ------------------------/
def upload_manuscript(request):
    if request.method == 'POST':
        pdf_file = request.FILES.get('pdf_file')

        if pdf_file:
            manuscript = Manuscript(
                pdf_file=pdf_file,
                student=request.user,
            )
            manuscript.save()

            pdf_file_path = manuscript.pdf_file.path

            if os.path.exists(pdf_file_path):
                try:
                    pages = convert_from_path(pdf_file_path, dpi=72)

                    if len(pages) >= 2:
                        abstract_image = pages[1]
                        abstract_text = pytesseract.image_to_string(abstract_image).strip()

                        if "Abstract" in abstract_text:
                            abstract_text = abstract_text.split("Abstract", 1)[1].strip()
                        else:
                            abstract_text = "No abstract found"

                        manuscript.abstracts = abstract_text

                except Exception as e:
                    print(f"Error processing PDF: {e}")

            manuscript.save()

            return redirect('final_manuscript_page', manuscript_id=manuscript.id, extracted_abstract=manuscript.abstracts)

    return render(request, 'ccsrepo_app/manuscript_upload_page.html')




def final_manuscript_page(request, manuscript_id, extracted_abstract=""):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    if request.method == 'POST':
        title = request.POST.get('title')
        authors = request.POST.get('authors')
        category_id = request.POST.get('category')
        batch_id = request.POST.get('batch')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')
        keywords = request.POST.get('keywords')
        adviser_id = request.POST.get('adviser')

        adviser = CustomUser.objects.get(id=adviser_id)

        manuscript.title = title
        manuscript.authors = authors
        manuscript.category_id = category_id
        manuscript.batch_id = batch_id
        manuscript.manuscript_type_id = manuscript_type_id
        manuscript.program_id = program_id
        manuscript.adviser = adviser
        manuscript.publication_date = timezone.now().date()

        manuscript.save()

        if keywords:
            keywords_list = [keyword.strip() for keyword in keywords.split(',')]
            for word in keywords_list:
                keyword, _ = Keyword.objects.get_or_create(word=word)
                manuscript.keywords.add(keyword)

        return redirect('dashboard')

    categories = Category.objects.all()
    batches = Batch.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    programs = Program.objects.all()
    advisers = CustomUser.objects.filter(is_adviser=True)

    return render(request, 'ccsrepo_app/manuscript_final_page.html', {
        'manuscript': manuscript,
        'extracted_abstract': extracted_abstract,  # Pass extracted abstract to template
        'categories': categories,
        'batches': batches,
        'manuscript_types': manuscript_types,
        'programs': programs,
        'advisers': advisers,
    })

#----------------End Manuscript System ------------------------/

#----------------Adviser System ------------------------/
def adviser_manuscript(request):
    manuscripts = Manuscript.objects.filter(adviser=request.user)

    return render(request, 'ccsrepo_app/adviser_manuscript.html', {
        'manuscripts': manuscripts,
    })


def adviser_review(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id, adviser=request.user)

    if request.method == 'POST':
        feedback = request.POST.get('feedback')
        decision = request.POST.get('decision')

        # Update feedback
        manuscript.feedback = feedback
        
        # Update approval status based on the decision
        if decision == 'approve':
            manuscript.is_approved = True  # Set as approved
        elif decision == 'reject':
            manuscript.is_approved = False  # Set as rejected
        else:
            # Handle case where decision is not recognized, if necessary
            pass
        
        manuscript.save()

        return redirect('adviser_manuscript')

    return render(request, 'ccsrepo_app/adviser_review.html', {
        'manuscript': manuscript
    })

#----------------End Adviser System ------------------------/

#----------------Student System ------------------------/
def student_manuscripts_view(request):
    # Ensure the user is authenticated and is a student
    if request.user.is_authenticated and request.user.is_student:
        # Get all manuscripts submitted by the logged-in student
        manuscripts = Manuscript.objects.filter(student=request.user)

        return render(request, 'ccsrepo_app/student_manuscript.html', {
            'manuscripts': manuscripts,
        })
    
#----------------End Student System ------------------------/




