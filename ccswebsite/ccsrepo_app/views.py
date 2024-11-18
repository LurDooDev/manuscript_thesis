from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.contrib import messages
from django.utils import timezone
import os
from django.db.models import Q 
import pytesseract
from .models import CustomUser, Program, Category, ManuscriptType, Batch, AdviserStudentRelationship, Manuscript, PageOCRData, ManuscriptAccessRequest, Keyword
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from io import BytesIO
from django.db.models import Count
from django.http import JsonResponse
from django.utils.html import mark_safe
import re
from PIL import Image
import fitz
from django.core.exceptions import ObjectDoesNotExist

#----------------Search and Manuscript flow System ------------------------/
def get_filtered_manuscripts(search_query, program_id=None, manuscript_type_id=None, category_id=None):
    # Get all approved manuscripts
    manuscripts = Manuscript.objects.filter(status='approved')

    # Filter based on search query for title, abstracts, batch name, and category
    if search_query:
        manuscripts = manuscripts.filter(
            Q(title__icontains=search_query) |
            Q(abstracts__icontains=search_query) |
            Q(year__icontains=search_query) |
            Q(category__name__icontains=search_query) |
            Q(adviser__first_name__icontains=search_query) |
            Q(adviser__last_name__icontains=search_query) |
            Q(authors__icontains=search_query) |
            Q(program__name__icontains=search_query) |
            Q(manuscript_type__name__icontains=search_query)
        )

    # Filter by program, manuscript type, category, and batch if specified
    if program_id:
        manuscripts = manuscripts.filter(program_id=program_id)
    if manuscript_type_id:
        manuscripts = manuscripts.filter(manuscript_type_id=manuscript_type_id)
    if category_id:
        manuscripts = manuscripts.filter(category_id=category_id)

    return manuscripts.order_by('-publication_date')

def manuscript_search_page(request):
    search_query = request.GET.get('search', '')
    program_id = request.GET.get('program')
    manuscript_type_id = request.GET.get('manuscript_type')
    category_id = request.GET.get('category')

    # Get filtered manuscripts based on search query and filters
    manuscripts = get_filtered_manuscripts(search_query, program_id, manuscript_type_id, category_id)

    # Retrieve additional filter options
    programs = Program.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    categories = Category.objects.all()

    # Pagination
    paginator = Paginator(manuscripts, 5)
    page_number = request.GET.get('page')
    manuscripts = paginator.get_page(page_number)

    return render(request, 'ccsrepo_app/manuscript_search_page.html', {
        'manuscripts': manuscripts,
        'search_query': search_query,
        'programs': programs,
        'manuscript_types': manuscript_types,
        'categories': categories,
    })

def view_manuscript(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    # Check if the user is the student or adviser of the manuscript
    is_student = request.user == manuscript.student
    
    # Check if the user is an admin
    is_admin = request.user.is_admin
    is_adviser = request.user.is_adviser

    # Check if the user has an approved access request
    access_request = ManuscriptAccessRequest.objects.filter(
        manuscript=manuscript,
        student=request.user,
        status='approved',
        access_start_date__lte=timezone.now(),
        access_end_date__gte=timezone.now()
    ).first()
    
    # Check if the user has a pending access request
    has_pending_request = ManuscriptAccessRequest.objects.filter(
        manuscript=manuscript,
        student=request.user,
        status='pending'
    ).exists()

    # Set has_access to True if the user is the student, adviser, admin, or has an approved request
    has_access = is_student or is_adviser or is_admin or (access_request is not None)

    return render(request, 'ccsrepo_app/view_manuscript.html', {
        'manuscript': manuscript,
        'has_access': has_access,
        'has_pending_request': has_pending_request,
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

        if user is not None and user.is_active:
            login(request, user)

            # Redirect based on user type
            if user.is_student:
                return redirect('manuscript_search_page')

            elif user.is_adviser:
                return redirect('adviser_approve_student')

            elif user.is_admin:
                return redirect('manage_users')

            # If the user is active but does not fit into student, adviser, or admin roles
            messages.info(request, "Logged in successfully. You can send requests to advisers.")
            return redirect('adviser_request')

        else:
            messages.error(request, "Invalid username or password. Please try again.")
            return redirect('login')

    return render(request, 'ccsrepo_app/login.html')

#----------------Student and Adviser ------------------------/
#View of Request to Adviser
def success_request_view(request):
    return render(request, 'ccsrepo_app/adviser_request_success.html')

@login_required(login_url='login')
def request_adviser_view(request):
    print(f"Current user: {request.user}")

    if request.method == 'POST':
        adviser_email = request.POST.get('email')
        student = request.user 

        try:
            adviser = CustomUser.objects.get(email=adviser_email, is_adviser=True)

            # Check if there's already an approved relationship with the adviser
            existing_relationship = AdviserStudentRelationship.objects.filter(adviser=adviser, student=student).first()

            if existing_relationship:
                if existing_relationship.status == 'approved':
                    messages.warning(request, "You have already been approved by this adviser.")
                else:
                    messages.warning(request, "You have already sent a request to this adviser.")
            else:
                # Create a new adviser-student relationship with 'pending' status
                AdviserStudentRelationship.objects.create(adviser=adviser, student=student, status='pending')
                messages.success(request, "Your request has been sent to your adviser.")
                return redirect('adviser_request_success')

        except CustomUser.DoesNotExist:
            messages.error(request, "No adviser found with this email or they are not an adviser.")
        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")

    return render(request, 'ccsrepo_app/adviser_request.html')

def approve_student_view(request):
    if not request.user.is_adviser:
        messages.error(request, "You are not authorized to approve students.")
        return redirect('dashboard')

    # Get all relationships where the logged-in user is the adviser, ordered by created_at
    relationships = AdviserStudentRelationship.objects.filter(adviser=request.user).order_by('-created_at')

    # Pagination setup: Show 5 relationships per page
    paginator = Paginator(relationships, 5)  # 5 relationships per page
    page_number = request.GET.get('page')  # Get the page number from URL
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST':
        student_id = request.POST.get('student_id')
        try:
            # Get the student relationship for the adviser
            student_relationship = get_object_or_404(AdviserStudentRelationship, id=student_id, adviser=request.user)
            
            # Get the student from the relationship
            student = student_relationship.student

            # Check if the status is already approved before updating
            if student_relationship.status != 'approved':
                # Update the status of the relationship to approved
                student_relationship.status = AdviserStudentRelationship.APPROVED  # Assuming you added the constant 'APPROVED'
                student_relationship.save()

                # Optionally, set the student role to True if needed (e.g., if your CustomUser model has is_student)
                student.is_student = True  # Set the is_student flag
                student.save()  # Save the student object

                messages.success(request, f"{student.username} has been approved as a student.")
            else:
                messages.info(request, f"{student.username} has already been approved.")

            return redirect('adviser_approve_student')

        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")

    return render(request, 'ccsrepo_app/adviser_approve_student.html', {'page_obj': page_obj})

#----------------End Student and Adviser ------------------------/
#----------------Register ------------------------/
def validate_user_password(password):
    errors = []
    if len(password) < 8:
        errors.append(_("Password must be at least 8 characters long."))
    if not any(char.isupper() for char in password):
        errors.append(_("Password must contain at least one uppercase letter."))
    if not any(char.islower() for char in password):
        errors.append(_("Password must contain at least one lowercase letter."))
    if not any(char.isdigit() for char in password):
        errors.append(_("Password must contain at least one digit."))
    if not any(char in '!@#$%^&*()-_=+[]{}|;:,.<>?/' for char in password):
        errors.append(_("Password must contain at least one special character."))
    
    return errors

def validate_user_data(email, username, password1, password2):
    errors = {}

    # Updated email pattern: two letters, a four-digit year, five digits, and the domain
    email_pattern = r"^[a-zA-Z]{2}\d{4}\d{5}@wmsu\.edu\.ph$"
    if not re.match(email_pattern, email):
        errors['email'] = [_("Email must be wmsu email")]

    # Validate password with custom rules
    password_errors = validate_user_password(password1)
    if password_errors:
        errors['password1'] = password_errors

    # Check if passwords match
    if password1 != password2:
        errors['password2'] = [_("Passwords do not match.")]

    # Validate using Django's built-in password validators
    try:
        password_validation.validate_password(password1)
    except ValidationError as e:
        errors['password1'] = errors.get('password1', []) + list(e.messages)

    # Check if email or username already exists
    if CustomUser.objects.filter(email=email).exists():
        errors['email'] = errors.get('email', []) + [_("Email already exists.")]
    if CustomUser.objects.filter(username=username).exists():
        errors['username'] = [_("Username already exists.")]

    return errors

def StudentRegister(request):
    if request.method == 'POST':
        # Retrieve and strip form data
        email = request.POST.get('email', '').strip()
        username = request.POST.get('username', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        middle_name = request.POST.get('middle_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        password1 = request.POST.get('password1', '').strip()
        password2 = request.POST.get('password2', '').strip()
        program_id = request.POST.get('program')

        # Validate user data
        errors = validate_user_data(email, username, password1, password2)

        # If there are errors, re-render the form with errors and the previously entered data
        if errors:
            programs = Program.objects.all()
            # Add the current form data to the context
            return render(request, 'ccsrepo_app/register.html', {
                'programs': programs,
                'errors': errors,
                'email': email,
                'username': username,
                'first_name': first_name,
                'middle_name': middle_name,
                'last_name': last_name,
                'program_id': program_id
            })

        # If validation passes, create the user
        user = CustomUser(
            email=email,
            username=username,
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            is_student=False,
            program_id=program_id
        )
        user.set_password(password1)  # Use the hashed password method
        user.save()
        
        messages.success(request, "Registration successful!")
        return redirect('login')
    
    programs = Program.objects.all()
    return render(request, 'ccsrepo_app/register.html', {'programs': programs})
#----------------End Register------------------------/

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

#Dashboard Page
def dashboard_page(request):
    # Get manuscripts with specific statuses
    advisers = CustomUser.objects.filter(is_adviser=True).annotate(manuscript_count=Count('manuscripts')
    )
    programs = Program.objects.annotate(
        manuscript_count=Count('manuscript')  # Count all manuscripts related to each program
    )
    types = ManuscriptType.objects.annotate(
        manuscript_count=Count('manuscript')  # Count all manuscripts related to each program
    )
    
    manuscripts = Manuscript.objects.all()
    approved_manuscripts = Manuscript.objects.filter(status='approved')
    pending_manuscripts = Manuscript.objects.filter(status='pending')
    rejected_manuscript = Manuscript.objects.filter(status = 'rejected')
    adviser_names = [adviser.first_name + ' ' + adviser.last_name for adviser in advisers]
    
    # Count manuscripts by status
    pending_count = pending_manuscripts.count()
    approved_count = approved_manuscripts.count()
    rejected_count = rejected_manuscript.count()
    adviser_count = advisers.count()
    manuscript_counts = [adviser.manuscript_count for adviser in advisers]
    total_records = Manuscript.objects.all().count()  # Total manuscripts count

    # Pass manuscripts and counts to the template
    context = {
        'approved_count': approved_count,
        'pending_count': pending_count,
        'rejected_count': rejected_count,
        'adviser_count': adviser_count,
        'manuscript_counts': manuscript_counts,
        
        'manuscripts': manuscripts,
        'total_records': total_records,
        'advisers': advisers,
        'adviser_names': adviser_names,
        'programs': programs,
        'types': types,
    }
    return render(request, 'ccsrepo_app/dashboard_page.html', context)

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

def edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)

    if request.method == 'POST':
        name = request.POST.get('name')

        if Category.objects.filter(name=name).exists() and name != category.name:
            messages.error(request, "A category with this name already exists.")
            return redirect('edit_category', category_id=category.id)

        category.name = name
        category.save()
        messages.success(request, "Category updated successfully.")
        return redirect('manage_category')

    return render(request, 'ccsrepo_app/edit_category.html', {'category': category})

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

#new manage adviser
def ManageAdviser(request):
    if request.method == 'POST':
        email = request.POST.get('email').strip()
        username = request.POST.get('username').strip()
        first_name = request.POST.get('first_name').strip()
        middle_name = request.POST.get('middle_name').strip()
        last_name = request.POST.get('last_name').strip()
        password1 = request.POST.get('password1').strip()
        password2 = request.POST.get('password2').strip()
        program_id = request.POST.get('program')

        # Validate user data
        errors = validate_user_data(email, username, password1, password2)

        # If there are errors, re-render the form with errors and the previously entered data
        if errors:
            programs = Program.objects.all()
            advisers = CustomUser.objects.filter(is_adviser = True)
            return render(request, 'ccsrepo_app/manage_users.html', {
                'programs': programs,
                'advisers': advisers,
                'errors': errors,
                'email': email,
                'username': username,
                'first_name': first_name,
                'middle_name': middle_name,
                'last_name': last_name,
                'program_id': program_id
            })

        # Create the user if validation passes
        user = CustomUser(
            email=email,
            username=username,
            first_name=first_name,
            middle_name=middle_name,
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
    return render(request, 'ccsrepo_app/manage_users.html', {
        'advisers': advisers,
        'programs': programs
    })

def validate_adviser_data(email, username, password1, password2):
    errors = {}
    
    # Password validation
    try:
        password_validation.validate_password(password1)
    except ValidationError as e:
        errors['password1'] = list(e.messages)

    # Updated email pattern: two letters, a four-digit year, five digits, and the domain
    email_pattern = r"^[a-zA-Z]{2}\d{4}\d{5}@wmsu\.edu\.ph$"
    if not re.match(email_pattern, email):
        errors['email'] = [_("Email must be wmsu email")]

    # Check if passwords match
    if password1 != password2:
        errors['password2'] = ["Passwords do not match."]

    # Check if email already exists
    if CustomUser.objects.filter(email=email).exists():
        errors['email'] = ["Email already exists."]

    # Check if username already exists
    if CustomUser.objects.filter(username=username).exists():
        errors['username'] = ["Username already exists."]
    
    return errors
#----------------End Admin Managing ------------------------/


#----------------Manuscript System ------------------------/
#----------------UTIL/Helper------------------------/

def validate_user_title(title):
    errors = []
    
    # Check if any other manuscript with the same title has upload_show=True
    if Manuscript.objects.filter(title=title, upload_show=True).exists():
        errors.append(_("A manuscript with this title is already published (upload_show=True). Please choose a different title."))
    
    return errors

CHUNK_SIZE = 2

def extract_title_from_first_page(first_page_text):
    """Extract and format the title from the first page."""
    title_text = first_page_text.replace('\n', ' ').strip()
    title_text = re.sub(r'\s+', ' ', title_text)  # Normalize spaces to a single space

    # Define possible start and end keywords for the title extraction
    title_start_keywords = ["Zamboanga City", "Department of Information Technology"]
    title_end_keywords = [
        "A thesis presented to the faculty", "In partial fulfillment",
        "A capstone project", "A CAPSTONE PROJECT"
    ]
    title_exclude_keywords = [
        "A CAPSTONE PROJECT Presented to the Faculty of the College of Computing Studies Western Mindanao State University"
    ]

    start_idx = end_idx = -1
    for start_keyword in title_start_keywords:
        start_idx = title_text.lower().find(start_keyword.lower())
        if start_idx != -1:
            break
    for end_keyword in title_end_keywords:
        temp_end_idx = title_text.lower().find(end_keyword.lower())
        if temp_end_idx != -1:
            end_idx = temp_end_idx
            break
    for exclude_keyword in title_exclude_keywords:
        exclude_idx = title_text.lower().find(exclude_keyword.lower())
        if exclude_idx != -1:
            end_idx = exclude_idx  # Adjust end index to exclude unwanted part
            break

    if start_idx != -1 and end_idx != -1:
        title = title_text[start_idx + len(title_start_keywords[0]): end_idx].strip()
        
        unwanted_prefixes = ["INFORMATION TECHNOLOGY", "Information Technology"]
        for prefix in unwanted_prefixes:
            if title.lower().startswith(prefix.lower()):
                title = title[len(prefix):].strip()
                break
        title = title.replace("&", "").strip()
        return title if title else "No title found"
    else:
        return "No title found"

def extract_year_from_first_page(first_page_text):
    """Extract the year from the first page."""
    year_match = re.search(r'\b(19|20)\d{2}\b', first_page_text)
    return year_match.group(0) if year_match else "Year not found"

def extract_authors_from_first_page(first_page_text):
    """Extract authors from the first page."""
    author_end_keywords = ["Researchers", "Researcher"]
    author_start_keywords = [
        "Bachelor of Science in Computer Science",
        "presented to the faculty of department of computer science college of computing studies"
    ]
    
    author_end_idx = -1
    for end_keyword in author_end_keywords:
        temp_end_idx = first_page_text.lower().find(end_keyword.lower())
        if temp_end_idx != -1:
            author_end_idx = temp_end_idx
            break

    if author_end_idx != -1:
        author_start_idx = -1
        for start_keyword in author_start_keywords:
            temp_start_idx = first_page_text.lower().rfind(start_keyword.lower(), 0, author_end_idx)
            if temp_start_idx != -1:
                author_start_idx = temp_start_idx + len(start_keyword)
                break

        if author_start_idx != -1:
            authors_text = first_page_text[author_start_idx:author_end_idx].strip()
            author_pattern = re.compile(r'([A-Z][a-z]*\.? ?){2,}')
            authors = [match.group(0).strip() for match in author_pattern.finditer(authors_text)]

            disallowed_keywords = ["Science", "Studies", "Computer"]
            authors = [
                author for author in authors
                if not any(keyword in author for keyword in disallowed_keywords)
            ]
            if authors:
                return ', '.join(authors)

    by_index = first_page_text.lower().find("by")
    if by_index != -1:
        following_text = first_page_text[by_index + len("by"):].strip()
        lines = following_text.splitlines()
        raw_authors = [line.strip() for line in lines if line.strip()][:3]

        formatted_authors = []
        for raw_author in raw_authors:
            parts = raw_author.split(', ')
            if len(parts) == 2:
                surname, given_names = parts[0], parts[1]
                formatted_authors.append(f"{given_names} {surname}")
            else:
                formatted_authors.append(raw_author)
        if formatted_authors:
            return ', '.join(formatted_authors)

    return "No authors found"

def extract_abstract_from_initial_pages(pdf_path, max_pages=7):
    """Extract the abstract from the first occurrence of 'abstract' or 'executive summary' in the initial pages of the PDF."""
    doc = fitz.open(pdf_path)
    for i in range(min(max_pages, doc.page_count)):
        page = doc.load_page(i)
        pix = page.get_pixmap(dpi=100)
        img = Image.open(BytesIO(pix.tobytes("png")))
        page_text = pytesseract.image_to_string(img).strip().lower()

        if page_text.startswith("abstract") or page_text.startswith("executive summary"):
            keyword = "abstract" if page_text.startswith("abstract") else "executive summary"
            abstract_text = page_text[len(keyword):].strip()

            if "keywords" in abstract_text:
                abstract_text = abstract_text.split("keywords")[0].strip()

            return abstract_text or "No abstract found"

    return "No abstract found"

def extract_ocr_data_chunk(pdf_path, manuscript, start_page, end_page):
    """Extract OCR data from a chunk of pages in the PDF."""
    doc = fitz.open(pdf_path)
    ocr_data_list = []

    for i in range(start_page, end_page):
        page = doc.load_page(i)
        pix = page.get_pixmap(dpi=100)
        img = Image.open(BytesIO(pix.tobytes("png")))
        page_text = pytesseract.image_to_string(img).strip()
        ocr_data_list.append(PageOCRData(manuscript=manuscript, page_num=i + 1, text=page_text))

    PageOCRData.objects.bulk_create(ocr_data_list)

def process_manuscript(pdf_path, manuscript):
    """Process the manuscript by extracting title, year, authors, abstract, and OCR data in chunks."""
    first_page = fitz.open(pdf_path).load_page(0)
    pix = first_page.get_pixmap(dpi=140)
    img = Image.open(BytesIO(pix.tobytes("png")))
    first_page_text = pytesseract.image_to_string(img).strip()

    title = extract_title_from_first_page(first_page_text)
    year = extract_year_from_first_page(first_page_text)
    authors = extract_authors_from_first_page(first_page_text)
    abstract_text = extract_abstract_from_initial_pages(pdf_path)

    manuscript.title = title
    manuscript.year = year
    manuscript.authors = authors
    manuscript.abstracts = abstract_text
    manuscript.save()

    doc = fitz.open(pdf_path)
    total_pages = len(doc)
    manuscript.page_count = total_pages
    manuscript.current_page_count = 0

    initial_pages_processed = min(8, total_pages)
    manuscript.remaining_page = max(total_pages - initial_pages_processed, 0)
    manuscript.current_page_count = initial_pages_processed
    manuscript.save()

    for start_page in range(1, initial_pages_processed, CHUNK_SIZE):
        end_page = min(start_page + CHUNK_SIZE, total_pages)
        extract_ocr_data_chunk(pdf_path, manuscript, start_page, end_page)

    manuscript.current_page_count = initial_pages_processed
    manuscript.save()

def upload_manuscript(request):
    if request.method == 'POST':
        pdf_file = request.FILES.get('pdf_file')

        if pdf_file:
            manuscript = Manuscript(
                pdf_file=pdf_file,
                student=request.user,
                abstracts="No abstract found"
            )
            manuscript.save()
            pdf_file_path = manuscript.pdf_file.path

            if os.path.exists(pdf_file_path):
                try:
                    process_manuscript(pdf_file_path, manuscript)
                except Exception as e:
                    print(f"Error processing PDF: {e}")

            return redirect('final_manuscript_page', manuscript_id=manuscript.id)

    return render(request, 'ccsrepo_app/manuscript_upload_page.html')

def final_manuscript_page(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    errors = []

    if request.method == 'POST':
        title = request.POST.get('title')
        abstracts = request.POST.get('abstracts')
        authors = request.POST.get('authors')
        year = request.POST.get('year')
        category_id = request.POST.get('category')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')
        adviser_id = request.POST.get('adviser')

        # Validate title uniqueness if upload_show=True
        if Manuscript.objects.filter(title=title, upload_show=True).exclude(id=manuscript.id).exists():
            errors.append(_("A manuscript with this title is already published. Please choose a different title."))

        # Lookup adviser and handle if adviser is not found
        try:
            adviser = CustomUser.objects.get(id=adviser_id, is_adviser=True)
        except ObjectDoesNotExist:
            errors.append(_("Adviser not found. Please check the adviser ID."))

        # If there are errors, return them to the template
        if errors:
            categories = Category.objects.all()
            manuscript_types = ManuscriptType.objects.all()
            programs = Program.objects.all()
            advisers = CustomUser.objects.filter(is_adviser=True)
            return render(request, 'ccsrepo_app/manuscript_final_page.html', {
                'manuscript': manuscript,
                'categories': categories,
                'manuscript_types': manuscript_types,
                'programs': programs,
                'advisers': advisers,
                'errors': errors,
            })

        # Assign validated fields to manuscript
        manuscript.title = title
        manuscript.abstracts = abstracts
        manuscript.authors = authors
        manuscript.year = year
        manuscript.category_id = category_id
        manuscript.manuscript_type_id = manuscript_type_id
        manuscript.program_id = program_id
        manuscript.adviser = adviser  # Set adviser after validation

        # Set publication date and update upload_show to True
        manuscript.publication_date = timezone.now()
        manuscript.upload_show = True

        manuscript.save()
        return redirect('manuscript_search_page')

    # Load choices for form in GET request
    categories = Category.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    programs = Program.objects.all()
    advisers = CustomUser.objects.filter(is_adviser=True)

    return render(request, 'ccsrepo_app/manuscript_final_page.html', {
        'manuscript': manuscript,
        'categories': categories,
        'manuscript_types': manuscript_types,
        'programs': programs,
        'advisers': advisers,
    })

#----------------End Manuscript System ------------------------/

#----------------Adviser System ------------------------/
def adviser_manuscript(request):
    manuscripts = Manuscript.objects.filter(adviser=request.user).exclude(student=request.user)

    return render(request, 'ccsrepo_app/adviser_manuscript.html', {
        'manuscripts': manuscripts,
    })


def adviser_review(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    if request.method == "POST":
        feedback = request.POST.get('feedback')
        decision = request.POST.get('decision')

        # Update feedback and status
        manuscript.feedback = feedback
        manuscript.status = "approved" if decision == "approve" else "rejected"
        manuscript.is_approved = True if decision == "approve" else False
        manuscript.publication_date = timezone.now()
        manuscript.save()

        return redirect('adviser_manuscript')

    return render(request, 'ccsrepo_app/adviser_review.html', {'manuscript': manuscript})

#----------------End Adviser System ------------------------/

#----------------Student System ------------------------/
def student_manuscripts_view(request):
    # Check if the user is authenticated and is a student
    if request.user.is_authenticated and request.user.is_student:
        # Get all manuscripts submitted by the logged-in student with upload_show=True
        manuscripts = Manuscript.objects.filter(student=request.user, upload_show=True)

        return render(request, 'ccsrepo_app/student_manuscript.html', {
            'manuscripts': manuscripts,
        })

def manuscript_detail_view(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    # Calculate the progress percentage if there are pages to process
    if manuscript.page_count > 0:
        progress_percentage = (manuscript.current_page_count / manuscript.page_count) * 100
    else:
        progress_percentage = 0

    # Add the calculated percentage to the context
    context = {
        'manuscript': manuscript,
        'progress_percentage': progress_percentage
    }

    return render(request, 'ccsrepo_app/manuscript_detail.html', context)

def extract_text_from_page(pdf_file, page_number):
    # Open the PDF file using PyMuPDF
    pdf_document = fitz.open(pdf_file.path)
    page = pdf_document.load_page(page_number - 1)  # Zero-indexed in PyMuPDF

    # Extract text using PyMuPDF (basic text extraction)
    ocr_text = page.get_text("text")

    # If no text was extracted, try using OCR on the page image
    if not ocr_text:
        print(f"No text found on page {page_number}. Attempting OCR...")
        # Convert the page to an image
        pix = page.get_pixmap()
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        
        # Perform OCR on the image
        ocr_text = pytesseract.image_to_string(img)

    return ocr_text

def continue_scanning(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    # Process the next 10 pages if there are remaining pages to process
    pages_to_process = 10
    current_page = manuscript.current_page_count

    # Ensure we don't go past the total number of pages
    pages_to_process = min(pages_to_process, manuscript.remaining_page)

    for i in range(pages_to_process):
        # Update page count and remaining pages
        page_number = current_page + i + 1
        ocr_text = extract_text_from_page(manuscript.pdf_file, page_number)

        # Save the OCR data to the PageOCRData model
        PageOCRData.objects.create(
            manuscript=manuscript,
            page_num=page_number,
            text=ocr_text
        )

    # Update the manuscript's page count and remaining pages
    manuscript.current_page_count += pages_to_process
    manuscript.remaining_page -= pages_to_process
    manuscript.save()

    # Redirect back to the manuscript details page
    return redirect('manuscript_detail', manuscript_id=manuscript.id)
#----------------End Student System ------------------------/

#----------------Faculty System ------------------------/
def faculty_manuscripts_view(request):
    if request.user.is_authenticated:
        manuscripts = Manuscript.objects.filter(student=request.user,  upload_show=True)

        return render(request, 'ccsrepo_app/faculty_manuscript.html', {
            'manuscripts': manuscripts,
        })

def faculty_detail_view(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    # Calculate the progress percentage if there are pages to process
    if manuscript.page_count > 0:
        progress_percentage = (manuscript.current_page_count / manuscript.page_count) * 100
    else:
        progress_percentage = 0

    # Add the calculated percentage to the context
    context = {
        'manuscript': manuscript,
        'progress_percentage': progress_percentage
    }
    return render(request, 'ccsrepo_app/faculty_detail.html', context)
#----------------Faculty Upload System ------------------------/
def faculty_upload_manuscript(request):
    if request.method == 'POST':
        pdf_file = request.FILES.get('pdf_file')

        if pdf_file:
            manuscript = Manuscript(
                pdf_file=pdf_file,
                student=request.user,
                abstracts="No abstract found"
            )
            manuscript.save()
            pdf_file_path = manuscript.pdf_file.path

            if os.path.exists(pdf_file_path):
                try:
                    process_manuscript(pdf_file_path, manuscript)
                except Exception as e:
                    print(f"Error processing PDF: {e}")

            # Redirect to the final confirmation page with the manuscript object
            return redirect('faculty_final_page', manuscript_id=manuscript.id)

    return render(request, 'ccsrepo_app/faculty_upload_page.html')

def faculty_final_page(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    errors = []

    if request.method == 'POST':
        title = request.POST.get('title')
        abstracts = request.POST.get('abstracts')
        authors = request.POST.get('authors')
        year = request.POST.get('year')
        category_id = request.POST.get('category')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')

        # Validate title uniqueness if upload_show=True
        if Manuscript.objects.filter(title=title, upload_show=True).exclude(id=manuscript.id).exists():
            errors.append(_("A manuscript with this title is already published. Please choose a different title."))

        # If there are errors, return them to the template
        if errors:
            categories = Category.objects.all()
            manuscript_types = ManuscriptType.objects.all()
            programs = Program.objects.all()
            return render(request, 'ccsrepo_app/faculty_final_page.html', {
                'manuscript': manuscript,
                'categories': categories,
                'manuscript_types': manuscript_types,
                'programs': programs,
                'errors': errors,
            })

        # Set adviser to the currently logged-in user
        adviser = request.user

        # Assign the manuscript fields from form data
        manuscript.title = title
        manuscript.abstracts = abstracts
        manuscript.authors = authors
        manuscript.year = year
        manuscript.category_id = category_id
        manuscript.manuscript_type_id = manuscript_type_id
        manuscript.program_id = program_id
        manuscript.adviser = adviser

        # Set publication date and update status and upload_show
        manuscript.publication_date = timezone.now()
        manuscript.status = 'approved'
        manuscript.upload_show = True

        manuscript.save()
        return redirect('manuscript_search_page')

    # Load choices for form in GET request
    categories = Category.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    programs = Program.objects.all()

    return render(request, 'ccsrepo_app/faculty_final_page.html', {
        'manuscript': manuscript,
        'categories': categories,
        'manuscript_types': manuscript_types,
        'programs': programs,
    })
#----------------End Faculty Upload System ------------------------/

# ----------------Request Access System ------------------------/
def request_access(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    
    # Check if the user is the assigned student or already has access
    if request.user.is_student and request.user == manuscript.student:
        return redirect('view_pdf', manuscript_id=manuscript.id)

    # Check if an access request already exists for this student and manuscript
    existing_request = ManuscriptAccessRequest.objects.filter(
        manuscript=manuscript, student=request.user, status='pending'
    ).exists()

    if not existing_request:
        # Create a new access request if none exists
        ManuscriptAccessRequest.objects.create(
            manuscript=manuscript,
            student=request.user,
        )
    return redirect('view_manuscript', manuscript_id=manuscript_id)

def manuscript_access_requests(request):
    # Query access requests, ordering by latest, and select related manuscript
    access_requests = ManuscriptAccessRequest.objects.filter(
        manuscript__adviser=request.user
    ).select_related('manuscript').order_by('-requested_at')
    
    # Paginate to show 5 requests per page
    paginator = Paginator(access_requests, 5)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'ccsrepo_app/manuscript_access_requests.html', {'page_obj': page_obj})

def manage_access_request(request):
    # Manage approval or denial of a request via a single endpoint
    if request.method == "POST":
        request_id = request.POST.get("request_id")
        action = request.POST.get("action")
        
        # Retrieve the access request and verify the adviser is responsible
        access_request = get_object_or_404(ManuscriptAccessRequest, id=request_id, manuscript__adviser=request.user)
        
        if action == "approve":
            # Approve and set the access duration
            access_request.approve(duration_days=7)
            messages.success(request, "Access request approved successfully.")
        elif action == "deny":
            # Deny the access request
            access_request.deny()
            messages.success(request, "Access request denied successfully.")
        
    return redirect("manuscript_access_requests")

def student_access_requests(request):
    if request.user.is_student:
        # Fetch access requests for the logged-in student
        access_requests = ManuscriptAccessRequest.objects.filter(student=request.user)
    else:
        access_requests = []  # No requests if the user is not a student

    return render(request, 'ccsrepo_app/student_access_requests.html', {'access_requests': access_requests})

def delete_unpublished_manuscripts(request):
    if request.method == 'POST':
        # Filter manuscripts where upload_show is False
        manuscripts_to_delete = Manuscript.objects.filter(upload_show=False)

        for manuscript in manuscripts_to_delete:
            # Delete related PageOCR records
            PageOCRData.objects.filter(manuscript=manuscript).delete()

            # Delete the PDF file from the filesystem
            if manuscript.pdf_file and os.path.isfile(manuscript.pdf_file.path):
                try:
                    os.remove(manuscript.pdf_file.path)
                    print(f"Deleted PDF file: {manuscript.pdf_file.path}")
                except Exception as e:
                    print(f"Failed to delete PDF file {manuscript.pdf_file.path}: {e}")

            # Delete the Manuscript itself
            manuscript.delete()
            print(f"Deleted manuscript: {manuscript.title}")

        messages.success(request, "Unpublished manuscripts have been successfully deleted.")
        return redirect('delete_unpublished_manuscripts')  # Redirect to your desired page after deletion
    return render(request, 'ccsrepo_app/delete_unpublished_manuscript.html')

# ----------------Indexing System ------------------------/
# Define the list of tech-related keywords
tech_related_keywords = [
    "machine learning", "artificial intelligence", "deep learning", "neural network", "data science",
    "python", "algorithm", "natural language processing", "computer vision", "big data", "cloud computing",
    "data analysis", "predictive modeling", "data mining", "automation", "robotics", "internet of things", 
    "AI", "IoT", "blockchain", "virtual reality", "augmented reality", "machine vision",
    "javascript", "node.js", "react", "angular", "vue.js", "express.js",
    "html", "css", "web development", "front-end", "back-end", "full-stack", "typescript", 
    "ruby on rails", "flutter", "swift", "kotlin", "c++", "c#", "go", "rust", "bash", "php", "sql", "nosql",
    "docker", "kubernetes", "aws", "azure", "gcp", "git", "gitlab", "github", "jenkins", "ci/cd", "tensorflow", 
    "keras", "pytorch", "scikit-learn", "matplotlib", "pandas", "numpy", "opencv", "django", "flask", "spark"
]

def extract_keywords_from_text(text):
    """
    Extract exact matches for keywords from a predefined list, ensuring only full matches.
    """
    # Convert text to lowercase to ensure case-insensitivity
    text = text.lower()
    
    # Only add full matches of keywords, preventing partial matches like "Java" for "JavaScript"
    keywords_found = []
    for keyword in tech_related_keywords:
        # Ensure we match the exact word (not a part of other words)
        if re.search(r'\b' + re.escape(keyword) + r'\b', text):
            keywords_found.append(keyword)
    
    # Return the found keywords (no duplicates)
    return list(set(keywords_found))

def extract_keywords_after_keywords(text):
    """
    Extract keywords after 'KEYWORDS:' section in the text.
    This function is specifically designed to capture keywords that follow 'KEYWORDS:' directly.
    """
    keywords_section = re.search(r'keywords:\s*(.*)', text, re.IGNORECASE)
    if keywords_section:
        keywords_str = keywords_section.group(1)
        # Split the keywords by commas or newlines and clean them
        keywords = [keyword.strip().lower() for keyword in keywords_str.split(',')]
        return keywords
    return []

def clean_and_extract_after_keywords(text):
    """
    Clean and extract content after 'CHAPTER', 'EXECUTIVE SUMMARY', or 'KEYWORDS:' keywords.
    """
    patterns = [
        r'(?<=\bchapter\b)(.*)',  # Match after "CHAPTER"
        r'(?<=\bexecutive summary\b)(.*)',  # Match after "EXECUTIVE SUMMARY"
        r'(?<=\bkeywords:\b)(.*)',  # Match after "KEYWORDS:"
    ]
    
    # Check for matches and return the first match (prioritize CHAPTER, EXECUTIVE SUMMARY, or KEYWORDS: )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()  # Return the content after the keyword
    
    return text  # If no match, return the original text

def view_pdf_manuscript(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    
    # Safely assign a value to 'search_term' even if it's not in the GET request
    search_term = request.GET.get('search', '').strip()  # Default to an empty string if 'search' is not in the GET request

    # Check if the manuscript is fully processed (current_page_count == page_count and remaining_page == 0)
    if manuscript.current_page_count == manuscript.page_count and manuscript.remaining_page == 0:
        # Get all OCR data for this manuscript
        pages = PageOCRData.objects.filter(manuscript=manuscript)

        # List to store all potential keywords from all pages
        all_keywords = []

        # Loop through each page's OCR data and extract keywords
        for page_data in pages:
            page_text = page_data.text.lower()  # Uniformly lowercase for consistent matching

            # Clean the text to extract content only after CHAPTER, EXECUTIVE SUMMARY, or KEYWORDS:
            cleaned_text = clean_and_extract_after_keywords(page_text)
            
            # Extract keywords based on tech-related terms
            page_keywords = extract_keywords_from_text(cleaned_text)
            all_keywords.extend(page_keywords)

            # Extract any additional keywords after 'KEYWORDS:' section
            additional_keywords = extract_keywords_after_keywords(page_text)
            all_keywords.extend(additional_keywords)

        # Deduplicate the keywords (set will remove duplicates)
        unique_keywords = list(set(all_keywords))

        # Limit the number of keywords to 5 or fewer
        limited_keywords = unique_keywords[:10]

        # Retrieve existing keywords for this manuscript
        existing_keywords = set(Keyword.objects.filter(manuscript=manuscript).values_list('keyword', flat=True))

        # Save only new keywords
        for keyword in limited_keywords:
            if keyword not in existing_keywords:
                Keyword.objects.create(manuscript=manuscript, keyword=keyword)

    # Prepare OCR data for the view
    if search_term:
        ocr_data = manuscript.ocr_data.filter(text__icontains=search_term).order_by('page_num')
        for page in ocr_data:
            highlighted_text = re.sub(
                f"({re.escape(search_term)})",
                r'<span class="highlight">\1</span>',
                page.text,
                flags=re.IGNORECASE
            )
            page.highlighted_text = mark_safe(highlighted_text)
    else:
        ocr_data = manuscript.ocr_data.all().order_by('page_num')
        for page in ocr_data:
            page.highlighted_text = page.text

    # Handle AJAX requests to return only OCR data
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        response_data = [{'page_num': page.page_num, 'highlighted_text': page.highlighted_text} for page in ocr_data]
        return JsonResponse({'ocr_data': response_data})

    # Collect matching page numbers for the search results
    matching_page_numbers = [page.page_num for page in ocr_data]

    return render(request, 'ccsrepo_app/view_pdf_manuscript.html', {
        'manuscript': manuscript,
        'ocr_data': ocr_data,
        'search_term': search_term,
        'matching_page_numbers': matching_page_numbers,
    })
# ----------------End Indexing System ------------------------/

# ----------------Visitor Site Flow System ------------------------/
def index_view(request):
    if request.method == 'GET' and 'q' in request.GET:
        search_query = request.GET.get('q')
        # Redirect to the search result page with the search query
        return redirect(f'/search/?q={search_query}')  # Use the exact URL of your search results page
    
    return render(request, 'index.html')

def visitor_search_manuscripts(request):
    search_query = request.GET.get('q', '')
    program_id = request.GET.get('program')
    manuscript_type_id = request.GET.get('manuscript_type')
    category_id = request.GET.get('category')

    # Get filtered manuscripts based on search query and filters
    manuscripts = get_filtered_manuscripts(search_query, program_id, manuscript_type_id, category_id)

    # Retrieve additional filter options
    programs = Program.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    categories = Category.objects.all()

    # Pagination
    paginator = Paginator(manuscripts, 5)
    page_number = request.GET.get('page')
    manuscripts = paginator.get_page(page_number)

    return render(request, 'visitor_search_result.html', {
        'manuscripts': manuscripts,
        'search_query': search_query,
        'programs': programs,
        'manuscript_types': manuscript_types,
        'categories': categories,
    })

def visitor_manuscript_detail(request, id):
    manuscript = Manuscript.objects.get(id=id)
    
    # Replace commas with <br> for the authors
    authors_with_br = manuscript.authors.replace(',', '<br>')

    return render(request, 'visitor_manuscript_detail.html', {
        'manuscript': manuscript,
        'authors_with_br': authors_with_br,
    })