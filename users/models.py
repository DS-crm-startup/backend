from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from users.managers import UserManager

class UserRole(models.TextChoices):
    Admin="Admin",'Admin'
    User="User",'User'
    Librarian="Librarian",'Librarian'

class CustomUser(AbstractUser):
    first_name = models.CharField(verbose_name="First Name", max_length=100)
    last_name = models.CharField(max_length=100,verbose_name="Last Name" )
    phone_number = models.CharField(unique=True,max_length=12)
    email = models.EmailField(unique=True,max_length=100)
    address=models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to="users/images/", null=True, blank=True)
    created_at = models.DateField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateField(auto_now=True, null=True, blank=True)
    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = []
    groups = models.ManyToManyField(Group, related_name="customuser_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="customuser_permissions", blank=True)
    objects = UserManager()

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def __str__(self):
        return self.first_name
