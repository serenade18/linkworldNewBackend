from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings  # ← add this

User = get_user_model()


class EmailOrUsernameBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        login_value = email or kwargs.get("username") or kwargs.get("email")
        if not login_value or not password:
            return None

        try:
            user = User.objects.get(email=login_value)
        except User.DoesNotExist:
            try:
                user = User.objects.get(username=login_value)
            except User.DoesNotExist:
                return None

        if user.check_password(password) and user.is_active:
            return user
        return None


class AllowInactiveJWTAuthentication(JWTAuthentication):
    """JWT auth that does NOT reject inactive users.

    Used for endpoints (e.g. KYC submission) that must be reachable while a
    professional account is still pending activation.
    """

    def get_user(self, validated_token):
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]  # ← use api_settings directly
        except KeyError:
            raise InvalidToken("Token contained no recognizable user identification")

        try:
            user = User.objects.get(**{api_settings.USER_ID_FIELD: user_id})  # ← same here
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found", code="user_not_found")

        # Intentionally skip the is_active check that the parent class does
        return user