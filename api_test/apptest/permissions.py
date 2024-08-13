from rest_framework.permissions import BasePermission

class HasUserPermission(BasePermission):
    def __init__(self, permission_id=None):
        self.permission_id = permission_id

    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if self.permission_id is not None:
            has_permission = request.user.user_permissions.filter(id=self.permission_id).exists()
            if not has_permission:
                print(f"El usuario {request.user.username} no tiene el permiso con ID {self.permission_id}")
            return has_permission
        return False
