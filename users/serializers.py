from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from users.models import VerificationModel, UserModel


class RegisterSerializers(serializers.Serializer):
    confirm_password = serializers.CharField(write_only=True, max_length=50)

    class Meta:
        fields = ('id', 'first_name', 'last_name', 'username', 'email', 'phone_number', 'password', 'confirm_password')
        extra_kwargs = {'password': {'write_only': True},
                        'first_name': {'required': False},
                        'last_name': {'required': False}
                        }

        def validate(self, attrs):
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')

            if password != confirm_password:
                raise serializers.ValidationError("Passwords do not match")
            try:
                validate_password(password=password)
            except ValidationError as e:
                raise serializers.ValidationError(e)

        def validate_email(self, email):
            if not email.endswith('@gmail.com') or not email.count('@') != 1:
                raise serializers.ValidationError("Invalid email address")
            return email


class VerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=4)

    def validate(self, attrs):
        try:
            user_code = VerificationModel.objects.get(email=attrs['email'], code=attrs['code'])
        except VerificationModel.DoesNotExist:
            raise serializers.ValidationError("Invalid verification code")

        if timezone.now() > user_code.created_at + timezone.timedelta(minutes=5):
            user_code.delete()
            raise serializers.ValidationError("Verification code has expired")
        return attrs


class LoginSerializer(serializers.Serializer):
    email_or_username = serializers.CharField(max_length=255)
    password = serializers.CharField(max_length=128)
    # remember_me = serializers.BooleanField(default=False)
    # access_token = serializers.CharField(max_length=255, read_only=True)
    # refresh_token = serializers.CharField(max_length=255, read_only=True)
    # expires_in = serializers.IntegerField(read_only=True)
    error_messages = 'Email or username or password are required fields'

    def validate(self, attrs):
        email_or_username = attrs.get('email_or_username')

        try:
            if email_or_username.endswith('@gmail.com'):
                user = UserModel.objects.get(email=email_or_username)
            else:
                user = UserModel.objects.get(username=email_or_username)
        except UserModel.DoesNotExist:
            raise serializers.ValidationError(self.error_messages)

        authenticated_user = authenticate(username=user.username, password=user.password)

        if not authenticated_user:
            raise serializers.ValidationError(self.error_messages)
        return attrs
