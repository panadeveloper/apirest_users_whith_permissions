import logging
from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import CustomUser

class CustomUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number', 'is_active', 'is_staff', 'password']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        logging.debug(f"Trying to authenticate user with email: {email}")

        # Autenticar usuario
        user = authenticate(request=self.context.get('request'), email=email, password=password)

        if not user:
            logging.error(f"Authentication failed for email: {email}")
            raise serializers.ValidationError('Usuario o contraseña incorrectos.')

        if not user.is_active:
            raise serializers.ValidationError('El usuario se encuentra inactivo, por lo que no tiene la posibilidad de iniciar sesión.')

        # Generar el token de acceso y devolver los datos
        data = super().validate(attrs)
        data['user'] = user
        return data
