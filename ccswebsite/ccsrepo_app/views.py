from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.utils import timezone
import os
import pytesseract
from pdf2image import convert_from_path
from .models import CustomUser, Program, Category, ManuscriptType, Batch, AdviserStudentRelationship, Manuscript, Keyword
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator

# Mock data for manuscripts (this should be replaced with actual data from your database)
manuscripts = [
    {"id": 1, "title": "AI in Education", "author": "John Doe", "batch": "2023-2024", "course": "BSCS", "category": "Machine Learning"},
    {"id": 2, "title": "Blockchain Technology", "author": "Jane Smith", "batch": "2022-2023", "course": "BSIT", "category": "Finance"},
    {"id": 3, "title": "Cybersecurity Trends", "author": "Mike Lee", "batch": "2023-2024", "course": "MIT", "category": "Security"},
    {"id": 4, "title": "Hello", "author": "Sponge Lee", "batch": "2024-2025", "course": "MIT", "category": "Technology"},
    {"id": 5, "title": "Kitty", "author": "Bruce Lee", "batch": "2025-2026", "course": "MIT", "category": "Animals"},
    {"id": 6, "title": "Ball", "author": "Jep Lee", "batch": "2026-2027", "course": "MIT", "category": "Sports"},
    {"id": 7, "title": "Skynet", "author": "Taguro Lee", "batch": "2025-2026", "course": "BSCS", "category": "Mobile Development"},
    {"id": 8, "title": "Robotics", "author": "Fugiro Lee", "batch": "2026-2027", "course": "BSIT", "category": "Web Development"},
    # Add more manuscripts...
]

def search_page(request):
    search_query = request.GET.get('search', '')
    selected_course = request.GET.get('course', 'All')
    selected_category = request.GET.get('category', 'All')
    selected_batch = request.GET.get('batch', 'All')
    current_page = request.GET.get('page', 1)

    # Filter manuscripts based on search, course, category, and batch
    filtered_manuscripts = [
        manuscript for manuscript in manuscripts
        if (search_query.lower() in manuscript["title"].lower())
        and (selected_course == 'All' or manuscript["course"] == selected_course)
        and (selected_category == 'All' or manuscript["category"] == selected_category)
        and (selected_batch == 'All' or manuscript["batch"] == selected_batch)
    ]

    # Pagination
    paginator = Paginator(filtered_manuscripts, 4)  # 4 manuscripts per page
    manuscripts_page = paginator.get_page(current_page)

    context = {
        'manuscripts': manuscripts_page,
        'total_pages': paginator.num_pages,
        'current_page': manuscripts_page.number,
        'search_query': search_query,
        'selected_course': selected_course,
        'selected_category': selected_category,
        'selected_batch': selected_batch,
    }
    return render(request, 'ccsrepo_app/manuscript_search_page.html', context)
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

            # Redirect advisers and admins to the dashboard
            elif user.is_adviser or user.is_admin:
                login(request, user)
                return redirect('dashboard')  # Redirect to dashboard for advisers and admins

            else:
                messages.warning(request, "Your account is not registered as a student. Please contact your adviser.")
                login(request, user)
                return redirect('adviser_request')  # Handle non-students

        else:
            messages.error(request, "Invalid username or password. Please try again.")
            return redirect('login')  # If login fails, redirect to the login page

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
        # Extract data from the request
        title = request.POST.get('title')
        pdf_file = request.FILES.get('pdf_file')
        authors = request.POST.get('authors')
        category_id = request.POST.get('category')
        batch_id = request.POST.get('batch')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')
        keywords = request.POST.get('keywords')
        adviser_id = request.POST.get('adviser')
        
        adviser = CustomUser.objects.get(id=adviser_id)

        # Create the manuscript instance and save to ensure file is stored
        manuscript = Manuscript(
            title=title,
            pdf_file=pdf_file,
            student=request.user,  # Set the student as the uploader
            authors=authors,
            category_id=category_id,
            batch_id=batch_id,
            manuscript_type_id=manuscript_type_id,
            program_id=program_id,
            publication_date=timezone.now().date(),  # Set current date as default
            adviser=adviser,
            status='pending',
            allowed_student=False
        )

        # Save the manuscript first to ensure the file is saved
        manuscript.save()

        # Extract the PDF file path
        pdf_file_path = manuscript.pdf_file.path

        if os.path.exists(pdf_file_path):
            try:
                # Convert the PDF to images
                pages = convert_from_path(pdf_file_path, dpi=72)

                # Assuming the abstract is on the second page
                if len(pages) >= 2:
                    abstract_image = pages[1]  # Get the second page as an image
                    abstract_text = pytesseract.image_to_string(abstract_image)  # Extract text from the image

                    # Get the first 300 words
                    words = abstract_text.split()  # Split the text into words
                    first_300_words = ' '.join(words[:300])  # Join the first 300 words back into a string
                    manuscript.abstracts = first_300_words.strip()  # Populate the abstracts field

            except Exception as e:
                print(f"Error processing PDF: {e}")

        # Save the manuscript again with the abstract populated
        manuscript.save()

        # Process keywords
        if keywords:
            keywords_list = [keyword.strip() for keyword in keywords.split(',')]  # Split and strip whitespace
            for word in keywords_list:
                # Create or get the keyword object
                keyword, _ = Keyword.objects.get_or_create(word=word)
                manuscript.keywords.add(keyword)  # Associate the keyword with the manuscript

        return redirect('dashboard')  # Redirect to a success page or wherever you want
    
    categories = Category.objects.all()
    batches = Batch.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    programs = Program.objects.all()
    advisers = CustomUser.objects.filter(is_adviser=True)
    return render(request, 'ccsrepo_app/manuscript_upload_page.html', {
        'categories': categories,
        'batches': batches,
        'manuscript_types': manuscript_types,
        'programs': programs,
        'advisers': advisers
    })

# def upload_manuscript(request):
#     if request.method == 'POST':
#         # Extract data from the request
#         title = request.POST.get('title')
#         pdf_file = request.FILES.get('pdf_file')
#         category_id = request.POST.get('category')  # Assume category ID is sent
#         # keywords = request.POST.get('keywords')  # Keywords will be comma-separated
#         # publication_date = request.POST.get('publication_date')
#         # manuscript_type_id = request.POST.get('manuscript_type')  # Assume manuscript type ID is sent
#         # program_id = request.POST.get('program')  # Assume program ID is sent

#         # Create the manuscript instance but do not save yet
#         manuscript = Manuscript(
#             title=title,
#             pdf_file=pdf_file,
#             category_id=category_id,
#             abstract = request.POST.get('abstract')
#             # publication_date=publication_date,
#             # manuscript_type_id=manuscript_type_id,
#             # program_id=program_id,
#             student=request.user  # Set the student as the uploader
#         )

#         # Extract text from PDF
#         pdf_file_path = manuscript.pdf_file.path
#         pages = convert_from_path(pdf_file_path, dpi=300)

#         # Assuming the abstract is on the second page
#         if len(pages) >= 2:
#             abstract_image = pages[1]  # Get the second page
#             abstract_text = pytesseract.image_to_string(abstract_image)
#             manuscript.abstracts = abstract_text.strip()  # Populate the abstract field
        
#         # Save the manuscript before adding keywords to avoid integrity issues
#         manuscript.save()

#         # # Handle keywords
#         # if keywords:
#         #     keywords_list = [keyword.strip() for keyword in keywords.split(',')]  # Split and strip whitespace
#         #     for word in keywords_list:
#         #         # Create or get the keyword object
#         #         keyword, created = Keyword.objects.get_or_create(word=word)
#         #         manuscript.keywords.add(keyword)  # Add the keyword to the manuscript

#         return redirect('dashboard')  # Redirect to a success page or wherever you want

#     return render(request, 'ccsrepo_app/manuscript_upload_page.html')


def finalize_manuscript_submission(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        abstract = request.POST.get('abstract')
        keywords = request.POST.get('keywords')
        citations = request.POST.get('citations')
        authors = request.POST.get('authors')
        pdf_file_url = request.POST.get('file')  # Use the file URL

        # Get additional form data
        category_id = request.POST.get('category')
        batch_id = request.POST.get('batch')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')
        adviser_id = request.POST.get('adviser')  # Get adviser ID from form

        # Assign the logged-in user as the student
        student = request.user

        # Get the adviser instance
        adviser = get_object_or_404(CustomUser, id=adviser_id)

        # Create the Manuscript instance
        manuscript = Manuscript(
            title=title,
            abstracts=abstract,
            citations=citations,
            authors=authors,
            category_id=category_id,
            batch_id=batch_id,
            manuscript_type_id=manuscript_type_id,
            program_id=program_id,
            pdf_file=pdf_file_url,  # Store URL instead of file object
            adviser=adviser,
            student=student,
            status='pending',
            allowed_student=False
        )
        manuscript.save()

        # Save keywords (assuming they're comma-separated)
        if keywords:
            for keyword in keywords.split(','):
                keyword_obj, _ = Keyword.objects.get_or_create(word=keyword.strip())
                manuscript.keywords.add(keyword_obj)


        manuscript.save()

        # Redirect to a success page
        return redirect('ccsrepo_app:manuscript_success')

    # If the request is not POST, redirect back to the manuscript review page
    return redirect('ccsrepo_app:manuscript_review')