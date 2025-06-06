from django.db import models
from django.contrib.auth.hashers import make_password, check_password

class AuthUser(models.Model):
    email = models.EmailField(unique=True, db_index=True)
    password = models.CharField(max_length=128)  # bcrypt hashed
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'auth_users'
        constraints = [
            models.UniqueConstraint(fields=['email'], name='unique_email_auth_user')
        ]

    def set_password(self, raw_password):
        """Hash and set the password using Django's built-in bcrypt hashing"""
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """Check the provided password against the stored hash"""
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.email