from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.views import APIView
from django.contrib.auth import logout as django_logout
from django.contrib.sessions.models import Session
from .serializers import CustomTokenObtainPairSerializer, CustomUserSerializer
from rest_framework.permissions import IsAuthenticated
from datetime import datetime, timedelta
from .models import CustomUser
from .permissions import HasUserPermission
from .serializers import serializers


class UserProfile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            if not user.is_authenticated:
                return Response({"error": "No se proporcionaron credenciales de autenticación."}, status=status.HTTP_401_UNAUTHORIZED)
            
            user_data = CustomUserSerializer(user).data
            permissions = user.user_permissions.values('id', 'name')  
            user_data['permissions'] = list(permissions)

            return Response(user_data)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CreateUser(APIView):
    
    
    def post(self, request, *args, **kwargs):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            response_data = {
                'user': serializer.data,
                'message': 'La creación del usuario se ha llevado a cabo con éxito.'
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ViewUser(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.has_perm('apptest.view_customuser'):
            return Response("El usuario no cuenta con los permisos necesarios para llevar a cabo estas funciones u operaciones.", status=status.HTTP_403_FORBIDDEN)

        user_id = self.kwargs.get('pk')
        try:
            user = CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        serializer = CustomUserSerializer(user)
        return Response(serializer.data)


class ListUser(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.has_perm('apptest.view_customuser'):
            return Response("El usuario no cuenta con los permisos necesarios para llevar a cabo estas funciones u operaciones.", status=status.HTTP_403_FORBIDDEN)

        users = CustomUser.objects.all()
        serializer = CustomUserSerializer(users, many=True)
        return Response(serializer.data)


class RegisterUsers(APIView):
    def post(self, request, *args, **kwargs):
        if not request.user.has_perm('apptest.add_customuser'):
            return Response("El usuario no cuenta con los permisos necesarios para llevar a cabo estas funciones u operaciones.", status=status.HTTP_403_FORBIDDEN)

        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.set_password(serializer.validated_data['password'])
            user.is_active = True 
            user.save()

            permissions = request.data.get('permissions', [])
            if permissions:
                for permission_id in permissions:
                    user.user_permissions.add(permission_id)
            
            token = AccessToken.for_user(user)
            token.set_exp(from_time=datetime.now() + timedelta(days=1))
            
            response_data = {
                "user": CustomUserSerializer(user).data,
                "TokenJWT": str(token),
                "message": "El usuario se ha creado de manera satisfactoria."
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateUser(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        if not request.user.has_perm('apptest.change_customuser'):
            return Response("El usuario no cuenta con los permisos necesarios para llevar a cabo estas funciones u operaciones.", status=status.HTTP_403_FORBIDDEN)

        user_id = self.kwargs.get('pk')
        try:
            user = CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class DeleteUser(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        if not request.user.has_perm('apptest.delete_customuser'):
            return Response("El usuario no cuenta con los permisos necesarios para llevar a cabo estas funciones u operaciones.", status=status.HTTP_403_FORBIDDEN)

        user_id = self.kwargs.get('pk')
        try:
            user = CustomUser.objects.get(pk=user_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

        user.delete()
        return Response({"message": "Usuario eliminado exitosamente."}, status=status.HTTP_204_NO_CONTENT)

class Login(APIView):
    def post(self, request, *args, **kwargs):
        serializer = CustomTokenObtainPairSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)

            user = serializer.validated_data.get("user")
            if not user:
                return Response({"error": "Error en la autenticación. No se encontró el usuario."}, status=status.HTTP_400_BAD_REQUEST)
            
            if not user.is_active:
                return Response({"error": "El usuario se encuentra inactivo, por lo que no tiene la posibilidad de iniciar sesión."}, status=status.HTTP_403_FORBIDDEN)
            
            TokenJWT = AccessToken.for_user(user)
            TokenJWT.set_exp(from_time=datetime.now() + timedelta(days=1))
            
            user_serializer = CustomUserSerializer(user)
            user_data = user_serializer.data
            
            is_admin = user.is_staff
            
            return Response({
                "TokenJWT": str(TokenJWT),
                "user": user_data,
                "is_admin": is_admin,
                "message": "Inicio de sesión exitoso."
            }, status=status.HTTP_200_OK)
        
        except serializers.ValidationError as e:
            error_message = e.detail[0] if isinstance(e.detail, list) else e.detail
            return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            return Response({"error": "No se proporcionaron credenciales de autenticación."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            access_token = auth_header.split()[1]
            token = AccessToken(access_token)
            if token.payload["user_id"] != request.user.id:
                return Response({"error": "El token JWT no pertenece a este usuario."}, status=status.HTTP_400_BAD_REQUEST)

            Session.objects.filter(expire_date__gte=datetime.now(), session_key__contains=str(token.payload["user_id"])).delete()
            tokens = OutstandingToken.objects.filter(user_id=request.user.id)
            for token in tokens:
                BlacklistedToken.objects.get_or_create(token=token)
            
            django_logout(request)
            return Response({"message": "Cierre de sesión exitoso."}, status=status.HTTP_200_OK)
        
        except IndexError:
            return Response({"error": "No se proporcionaron credenciales de autenticación."}, status=status.HTTP_400_BAD_REQUEST)
        except InvalidToken:
            return Response({"error": "Token JWT inválido o incorrecto."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
