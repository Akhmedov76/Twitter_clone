from rest_framework import generics
from rest_framework.permissions import AllowAny

from users.models import UserModel
from users.serializers import RegisterSerializers


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializers
    queryset = UserModel.objects.all()
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        user.set_password(serializer.validated_data['password'])
        user.is_active = False
        user.save()
        return user
