from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.utils import timezone
import os
from django.db.models import Q 
import pytesseract
from django.core.files.base import ContentFile
from pdf2image import convert_from_path
from .models import CustomUser, Program, Category, ManuscriptType, Batch, AdviserStudentRelationship, Manuscript, PageOCRData, ManuscriptAccessRequest
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from io import BytesIO
from django.db.models import Count

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'  # Update this path accordingly

#----------------UTIL/Helper------------------------/
def extract_pages_as_images(pdf_path, manuscript):
    pages = convert_from_path(pdf_path, dpi=72)
    for i, page in enumerate(pages):
        # Convert the page image to text using pytesseract
        page_text = pytesseract.image_to_string(page).strip()

        # Create a BytesIO object to save the image
        image_io = BytesIO()
        page.save(image_io, format='PNG')
        image_file = ContentFile(image_io.getvalue(), name=f"page_{i + 1}.png")

        # Save the OCR data for the page, including the image
        PageOCRData.objects.create(
            manuscript=manuscript,
            page_num=i + 1,
            text=page_text,
            image=image_file
        )
#----------------UTIL/Helper------------------------/

#----------------Search and Manuscript flow System ------------------------/
def get_filtered_manuscripts(search_query, program_id=None, manuscript_type_id=None, category_id=None, batch_id=None):
    # Get all approved manuscripts
    manuscripts = Manuscript.objects.filter(status='approved')

    # Filter based on search query for title, abstracts, batch name, and category
    if search_query:
        manuscripts = manuscripts.filter(
            Q(title__icontains=search_query) |
            Q(abstracts__icontains=search_query) |
            Q(batch__name__icontains=search_query) |
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
    if batch_id:
        manuscripts = manuscripts.filter(batch_id=batch_id)

    return manuscripts.order_by('-publication_date')

def manuscript_search_page(request):
    search_query = request.GET.get('search', '')
    program_id = request.GET.get('program')
    manuscript_type_id = request.GET.get('manuscript_type')
    category_id = request.GET.get('category')
    batch_id = request.GET.get('batch')

    # Get filtered manuscripts based on search query and filters
    manuscripts = get_filtered_manuscripts(search_query, program_id, manuscript_type_id, category_id, batch_id)

    # Retrieve additional filter options
    programs = Program.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    categories = Category.objects.all()
    batches = Batch.objects.all()

    # Pagination
    paginator = Paginator(manuscripts, 50)
    page_number = request.GET.get('page')
    manuscripts = paginator.get_page(page_number)

    return render(request, 'ccsrepo_app/manuscript_search_page.html', {
        'manuscripts': manuscripts,
        'search_query': search_query,
        'programs': programs,
        'manuscript_types': manuscript_types,
        'categories': categories,
        'batches': batches,
    })

def view_manuscript(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    # Check if the user is the student or adviser of the manuscript
    is_student = request.user == manuscript.student
    is_adviser = request.user == manuscript.adviser
    
    # Check if the user has an approved access request
    access_request = ManuscriptAccessRequest.objects.filter(
        manuscript=manuscript,
        student=request.user,
        status='approved',
        access_start_date__lte=timezone.now(),
        access_end_date__gte=timezone.now()
    ).first()
    
    # Set has_access to True if the user is the student, adviser, or has an approved request
    has_access = is_student or is_adviser or (access_request is not None)

    return render(request, 'ccsrepo_app/view_manuscript.html', {
        'manuscript': manuscript,
        'has_access': has_access,
    })

from django.utils.html import mark_safe
import re

# View PDF manuscript
def view_pdf_manuscript(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    pdf_url = manuscript.pdf_file.url

    search_term = request.GET.get('search', '').strip()
    
    # Prepare OCR data
    if search_term:
        # Filter OCR data to include all text (headings + body)
        ocr_data = manuscript.ocr_data.filter(text__icontains=search_term).order_by('page_num')
        
        for page in ocr_data:
            # Highlight both headings and body text
            highlighted_text = re.sub(
                f"({re.escape(search_term)})",
                r'<span class="highlight">\1</span>',
                page.text,
                flags=re.IGNORECASE
            )
            page.highlighted_text = mark_safe(highlighted_text)
    else:
        # If no search term, use the original text
        ocr_data = manuscript.ocr_data.all().order_by('page_num')
        for page in ocr_data:
            page.highlighted_text = page.text

    # Collect matching page numbers
    matching_page_numbers = [page.page_num for page in ocr_data]

    return render(request, 'ccsrepo_app/view_pdf_manuscript.html', {
        'manuscript': manuscript,
        'pdf_url': pdf_url,
        'ocr_data': ocr_data,
        'search_term': search_term,
        'matching_page_numbers': matching_page_numbers,
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

            # Check to prevent duplicates
            if AdviserStudentRelationship.objects.filter(adviser=adviser, student=student).exists():
                messages.warning(request, "You have already sent a request to this adviser.")
            else:
                # Create adviser-student relationship
                AdviserStudentRelationship.objects.create(adviser=adviser, student=student)
                messages.success(request, "Your request has been sent to your adviser.")
                return redirect('adviser_request_success')

        except CustomUser.DoesNotExist:
            messages.error(request, "No adviser found with this email or they are not an adviser.")
        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")

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

#Dashboard Page
def dashboard_page(request):
    # Get manuscripts with specific statuses
    advisers = CustomUser.objects.filter(is_adviser=True).annotate(manuscript_count=Count('manuscripts')
    )
    batches = Batch.objects.annotate(
        manuscript_count=Count('manuscript', distinct=True) 
    )
    programs = Program.objects.annotate(
        manuscript_count=Count('manuscript')  # Count all manuscripts related to each program
    )
    types = ManuscriptType.objects.annotate(
        manuscript_count=Count('manuscript')  # Count all manuscripts related to each program
    )
    manusripts = Manuscript.objects.all()
    
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
        'batches': batches,
        'programs': programs,
        'types': types,
        
        
    }

    return render(request, 'ccsrepo_app/dashboard_page.html', context)

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
                    # Extract pages and save images/text
                    extract_pages_as_images(pdf_file_path, manuscript)

                    pages = convert_from_path(pdf_file_path, dpi=72, poppler_path=r'C:\Program Files\poppler-24.08.0\Library\bin')
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

#Final Confirmation
def final_manuscript_page(request, manuscript_id, extracted_abstract=""):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    if request.method == 'POST':
        title = request.POST.get('title')
        authors = request.POST.get('authors')
        category_id = request.POST.get('category')
        batch_id = request.POST.get('batch')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')
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

        return redirect('dashboard')

    categories = Category.objects.all()
    batches = Batch.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    programs = Program.objects.all()
    advisers = CustomUser.objects.filter(is_adviser=True)

    return render(request, 'ccsrepo_app/manuscript_final_page.html', {
        'manuscript': manuscript,
        'extracted_abstract': extracted_abstract,
        'categories': categories,
        'batches': batches,
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
        manuscript.save()

        return redirect('adviser_manuscript')

    return render(request, 'ccsrepo_app/adviser_review.html', {'manuscript': manuscript})

#----------------End Adviser System ------------------------/

#----------------Student System ------------------------/
def student_manuscripts_view(request):
    # check and make sure user is authenticated and is_student
    if request.user.is_authenticated and request.user.is_student:
        # Get all manuscripts submitted by the logged-in student that have a non-empty title
        manuscripts = Manuscript.objects.filter(student=request.user, title__gt='')

        return render(request, 'ccsrepo_app/student_manuscript.html', {
            'manuscripts': manuscripts,
        })

def manuscript_detail_view(request, manuscript_id):
    # Retrieve manuscript using ID
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    return render(request, 'ccsrepo_app/manuscript_detail.html', {
        'manuscript': manuscript,
    })
#----------------End Student System ------------------------/

#----------------Faculty System ------------------------/
def faculty_manuscripts_view(request):
    if request.user.is_authenticated:
        manuscripts = Manuscript.objects.filter(student=request.user, title__gt='')

        return render(request, 'ccsrepo_app/faculty_manuscript.html', {
            'manuscripts': manuscripts,
        })

def faculty_detail_view(request, manuscript_id):
    # Retrieve the manuscript using the provided ID
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    return render(request, 'ccsrepo_app/faculty_detail.html', {
        'manuscript': manuscript,
    })


#----------------Faculty Upload System ------------------------/
def faculty_upload_manuscript(request):
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
                    extract_pages_as_images(pdf_file_path, manuscript)

                    pages = convert_from_path(pdf_file_path, dpi=72, poppler_path=r'C:\Program Files\poppler-24.08.0\Library\bin')
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

            return redirect('faculty_final_page', manuscript_id=manuscript.id, extracted_abstract=manuscript.abstracts)

    return render(request, 'ccsrepo_app/faculty_upload_page.html')

def faculty_final_page(request, manuscript_id, extracted_abstract=""):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    if request.method == 'POST':
        title = request.POST.get('title')
        authors = request.POST.get('authors')
        category_id = request.POST.get('category')
        batch_id = request.POST.get('batch')
        manuscript_type_id = request.POST.get('manuscript_type')
        program_id = request.POST.get('program')
        
        # Set adviser to the currently logged-in user
        adviser = request.user

        manuscript.title = title
        manuscript.authors = authors
        manuscript.category_id = category_id
        manuscript.batch_id = batch_id
        manuscript.manuscript_type_id = manuscript_type_id
        manuscript.program_id = program_id
        manuscript.adviser = adviser
        manuscript.publication_date = timezone.now().date()
        manuscript.status = 'approved'

        manuscript.save()

        return redirect('dashboard')

    categories = Category.objects.all()
    batches = Batch.objects.all()
    manuscript_types = ManuscriptType.objects.all()
    programs = Program.objects.all()

    return render(request, 'ccsrepo_app/faculty_final_page.html', {
        'manuscript': manuscript,
        'extracted_abstract': extracted_abstract,
        'categories': categories,
        'batches': batches,
        'manuscript_types': manuscript_types,
        'programs': programs,
    })
#----------------End Faculty Upload System ------------------------/

# ----------------Request Access System ------------------------/
def request_access(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    
    # Check if the user is the assigned student or already has access
    if request.user.is_student and request.user == manuscript.student:
        messages.info(request, "You already have access to this manuscript.")
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
        messages.success(request, "Your access request has been sent to the adviser for approval.")
    else:
        messages.info(request, "You have already requested access to this manuscript.")
    return redirect('manuscript_search_page')
    # return redirect('view_manuscript', manuscript_id=manuscript.id)

def manuscript_access_requests(request):
    # List all access requests for the adviser's manuscripts
    access_requests = ManuscriptAccessRequest.objects.filter(manuscript__adviser=request.user)
    return render(request, 'ccsrepo_app/manuscript_access_requests.html', {'access_requests': access_requests})

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