from rest_framework.permissions import BasePermission


class IsAdminRole(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "user_type", None) == "admin"
        )

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class IsDriverRole(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and getattr(request.user, "user_type", None) == "driver"
        )

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)
