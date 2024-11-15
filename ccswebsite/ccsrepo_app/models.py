from django.db import models
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager


#Users
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        if not username:
            raise ValueError("The Username field must be set")
        
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


#Program
class Program(models.Model):
    name = models.CharField(max_length=100, unique=True)
    abbreviation = models.CharField(max_length=10, unique=True)

    def __str__(self):
        return f"{self.name} ({self.abbreviation})"

#Category
class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name
    
class ManuscriptType(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

#Batch
class Batch(models.Model):
    name = models.CharField(max_length=4, unique=True)

    def __str__(self):
        return self.name
    
#users Create
class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=30, unique=True, default='bryan')
    first_name = models.CharField(max_length=30)
    middle_name = models.CharField(max_length=30, null=True, blank=True)
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_adviser = models.BooleanField(default=False)
    is_student = models.BooleanField(default=False)
    program = models.ForeignKey(Program, null=True, blank=True, on_delete=models.SET_NULL)
    manuscript_allow = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self):
        return  f"{self.first_name} {self.last_name}"

#Student and Adviser    
class AdviserStudentRelationship(models.Model):
    PENDING = 'pending'
    APPROVED = 'approved'
    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
    ]

    adviser = models.ForeignKey(CustomUser, related_name='adviser_relationships', on_delete=models.CASCADE)
    student = models.ForeignKey(CustomUser, related_name='student_relationships', on_delete=models.CASCADE)
    start_date = models.DateField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PENDING)

    def __str__(self):
        return f"{self.adviser.username} advises {self.student.username}"

#Manuscripts
class Manuscript(models.Model):
    title = models.TextField(max_length=255, null=True)
    abstracts = models.TextField(null=True, blank=True)
    authors = models.CharField(max_length=255)
    category = models.ForeignKey(Category, null=True, on_delete=models.CASCADE)
    publication_date = models.DateTimeField(null=True, blank=True)
    pdf_file = models.FileField(upload_to='manuscripts/')
    manuscript_type = models.ForeignKey(ManuscriptType, null=True, on_delete=models.CASCADE)
    program = models.ForeignKey(Program, null=True, on_delete=models.CASCADE)
    adviser = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='manuscripts')
    student = models.ForeignKey(CustomUser, null=True, on_delete=models.CASCADE, related_name='submitted_manuscripts')
    status = models.CharField(max_length=10, default='pending')
    allowed_student = models.BooleanField(default=False)
    feedback = models.TextField(null=True, blank=True)
    year = models.IntegerField(null=True, blank=True)
    upload_show= models.BooleanField(default=False)
    page_count = models.PositiveIntegerField(null=True, blank=True)
    remaining_page = models.PositiveIntegerField(null=True, blank=True)
    current_page_count = models.PositiveIntegerField(null=True, blank=True) 

    def __str__(self):
        return self.title

#PageOCRData for Pdf 
class PageOCRData(models.Model):
    manuscript = models.ForeignKey(Manuscript, related_name='ocr_data', on_delete=models.CASCADE)
    page_num = models.PositiveIntegerField()
    text = models.TextField()

    class Meta:
        unique_together = ('manuscript', 'page_num')
        
    def __str__(self):
        return f"Page {self.page_num} of {self.manuscript.title}"

#Request Access PDF
class ManuscriptAccessRequest(models.Model):
    manuscript = models.ForeignKey('Manuscript', on_delete=models.CASCADE, related_name='access_requests')
    student = models.ForeignKey('CustomUser', on_delete=models.CASCADE, related_name='access_requests')
    requested_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=10,
        choices=[('pending', 'Pending'), ('approved', 'Approved'), ('denied', 'Denied')],
        default='pending'
    )
    access_start_date = models.DateTimeField(null=True, blank=True)
    access_end_date = models.DateTimeField(null=True, blank=True)

    def approve(self, duration_days=7):
        """Approve the request and set access duration."""
        self.status = 'approved'
        self.approved_at = timezone.now()
        self.access_start_date = timezone.now()
        self.access_end_date = timezone.now() + timedelta(days=duration_days)
        self.save()

    def deny(self):
        """Deny the access request."""
        self.status = 'denied'
        self.save()

    def is_accessible(self):
        """Check if access is currently active."""
        if self.status == 'approved' and self.access_start_date and self.access_end_date:
            return self.access_start_date <= timezone.now() <= self.access_end_date
        return False

    @property
    def adviser(self):
        """Retrieve the adviser from the associated manuscript."""
        return self.manuscript.adviser
    
