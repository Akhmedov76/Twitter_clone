from django.contrib.auth.models import AbstractUser
from django.db import models


class UserModel(AbstractUser):
    email = models.CharField(max_length=50, blank=False, null=False, unique=True)


class VerificationModel(models.Model):
    user = models.OneToOneField(UserModel, on_delete=models.CASCADE, related_name='verification')
    code = models.CharField(max_length=5)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.user.username}-{self.code}'

    class Meta:
        verbose_name = 'verification'
        verbose_name_plural = 'verifications'
        ordering = ['-created_at']
        unique_together = ['user', 'code']
