from django.contrib import admin

from users.models import UserModel, VerificationModel

admin.site.register(UserModel)
admin.site.register(VerificationModel)
