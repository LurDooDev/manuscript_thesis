from django.db import models
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

#Type
class Type(models.Model):
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
    last_name = models.CharField(max_length=30)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_adviser = models.BooleanField(default=False)
    is_student = models.BooleanField(default=False)
    program = models.ForeignKey(Program, null=True, blank=True, on_delete=models.SET_NULL)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    def __str__(self):
        return self.email

#Student and Adviser    
class AdviserStudentRelationship(models.Model):
    adviser = models.ForeignKey(CustomUser, related_name='adviser_relationships', on_delete=models.CASCADE)
    student = models.ForeignKey(CustomUser, related_name='student_relationships', on_delete=models.CASCADE)
    start_date = models.DateField(auto_now_add=True)    

    def __str__(self):
        return f"{self.adviser.username} advises {self.student.username}"




