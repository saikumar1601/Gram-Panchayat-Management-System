from django.db import models

class users(models.Model):
    """
    Custom User model to match the SQL schema provided.
    """
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('employee', 'Employee'),
        ('citizen', 'Citizen'),
        ('government_monitor', 'Government Monitor'),
    ]

    user_id = models.AutoField(primary_key=True)  # SERIAL PRIMARY KEY equivalent
    password = models.CharField(max_length=100)
    username = models.CharField(max_length=50, unique=True)  # UNIQUE NOT NULL
    email = models.EmailField(max_length=100, unique=True)  # UNIQUE NOT NULL
    phone = models.CharField(max_length=15, blank=True, null=True)  # Optional phone number
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='citizen')  # Role with constraints
    registration_date = models.DateTimeField(auto_now_add=True)  # Default to current date

    def __str__(self):
        return self.username

    class Meta:
        db_table = 'users'