from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.utils import timezone
import os
from django.db.models import Q 
import pytesseract
from django.core.files.base import ContentFile
from pdf2image import convert_from_path
from .models import CustomUser, Program, Category, ManuscriptType, Batch, AdviserStudentRelationship, Manuscript, PageOCRData
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from io import BytesIO


#----------------UTIL/Helper------------------------/
def extract_pages_as_images(pdf_path, manuscript):
    pages = convert_from_path(pdf_path, dpi=72)  # Converts PDF to PIL images
    for i, page in enumerate(pages):
        # Convert the page image to text using pytesseract
        page_text = pytesseract.image_to_string(page).strip()

        # Create a BytesIO object to save the image
        image_io = BytesIO()
        page.save(image_io, format='PNG')  # Save page as PNG
        image_file = ContentFile(image_io.getvalue(), name=f"page_{i + 1}.png")

        # Save the OCR data for the page, including the image
        PageOCRData.objects.create(
            manuscript=manuscript,
            page_num=i + 1,
            text=page_text,
            image=image_file  # Save the image here
        )
#----------------UTIL/Helper------------------------/

#----------------Search and Manuscript flow System ------------------------/
def manuscript_search_page(request):
    search_query = request.GET.get('search', '')

    # Get all approved manuscripts
    manuscripts = Manuscript.objects.filter(status='approved')

    # Filter based on search query for title and related batch name
    if search_query:
        manuscripts = manuscripts.filter(
            Q(title__icontains=search_query) |
            Q(abstracts__icontains=search_query) |
            Q(batch__name__icontains=search_query) |
            Q(category__name__icontains=search_query) # Use 'name' or the appropriate field in Batch
        )

    # Order by publication date
    manuscripts = manuscripts.order_by('-publication_date')

    # Pagination (example with 10 manuscripts per page)
    paginator = Paginator(manuscripts, 10)
    page_number = request.GET.get('page')
    manuscripts = paginator.get_page(page_number)

    return render(request, 'ccsrepo_app/manuscript_search_page.html', {
        'manuscripts': manuscripts,
        'search_query': search_query,
    })

#View Manuscript
def view_manuscript(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    return render(request, 'ccsrepo_app/view_manuscript.html', {'manuscript': manuscript})

#View Pdf manuscript
def view_pdf_manuscript(request, manuscript_id):
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)
    pdf_url = manuscript.pdf_file.url  # Adjust as per your field name

    # Get the search term from GET parameters
    search_term = request.GET.get('search', '')
    
    # Filter OCR data based on search term
    if search_term:
        ocr_data = manuscript.ocr_data.filter(text__icontains=search_term).order_by('page_num')
    else:
        ocr_data = manuscript.ocr_data.all().order_by('page_num')

    # Extract page numbers that contain the search term
    matching_page_numbers = [page.page_num for page in ocr_data]

    return render(request, 'ccsrepo_app/view_pdf_manuscript.html', {
        'manuscript': manuscript,
        'pdf_url': pdf_url,
        'ocr_data': ocr_data,
        'search_term': search_term,
        'matching_page_numbers': matching_page_numbers,  # Pass matching page numbers to the template
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

        if user is not None and user.is_active:  # Check if the user exists and is active
            login(request, user)  # Log the user in

            # Redirect based on user type
            if user.is_student:
                return redirect('manuscript_search_page')  # Redirect to search page for students

            elif user.is_adviser:
                return redirect('adviser_approve_student')  # Redirect to adviser approval page

            elif user.is_admin:
                return redirect('manage_users')  # Redirect to manage users page

            # If the user is active but does not fit into student, adviser, or admin roles
            messages.info(request, "Logged in successfully. You can send requests to advisers.")
            return redirect('adviser_request')  # Redirect to adviser request page or wherever appropriate

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
    print(f"Current user: {request.user}")  # Debug print
    # Remove the is_student check

    if request.method == 'POST':
        adviser_email = request.POST.get('email')  # Use email instead of username
        student = request.user 

        try:
            adviser = CustomUser.objects.get(email=adviser_email, is_adviser=True)  # Fetch adviser by email

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
            messages.error(request, f"An error occurred: {str(e)}")  # Show actual error message for debugging

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
                    # Extract pages and save images/text
                    extract_pages_as_images(pdf_file_path, manuscript)

                    # If you want to specifically extract the abstract from the second page
                    pages = convert_from_path(pdf_file_path, dpi=72)  # You can reuse this if needed
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
    manuscripts = Manuscript.objects.filter(adviser=request.user)

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

        # Redirect to adviser manuscripts page after submitting
        return redirect('adviser_manuscript')

    return render(request, 'ccsrepo_app/adviser_review.html', {'manuscript': manuscript})

#----------------End Adviser System ------------------------/

#----------------Student System ------------------------/
def student_manuscripts_view(request):
    # Ensure the user is authenticated and is a student
    if request.user.is_authenticated and request.user.is_student:
        # Get all manuscripts submitted by the logged-in student that have a non-empty title
        manuscripts = Manuscript.objects.filter(student=request.user, title__gt='')

        return render(request, 'ccsrepo_app/student_manuscript.html', {
            'manuscripts': manuscripts,
        })

def manuscript_detail_view(request, manuscript_id):
    # Retrieve the manuscript using the provided ID
    manuscript = get_object_or_404(Manuscript, id=manuscript_id)

    return render(request, 'ccsrepo_app/manuscript_detail.html', {
        'manuscript': manuscript,
    })
#----------------End Student System ------------------------/






