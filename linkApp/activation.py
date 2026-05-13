"""Account activation endpoint — confirms the email link."""
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

User = get_user_model()


class ActivateAccountView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        return self._activate(uidb64, token)

    def post(self, request, uidb64, token):
        return self._activate(uidb64, token)

    def _activate(self, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"detail": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_active:
            return Response(
                {"detail": "Account is already active.", "already_active": True},
                status=status.HTTP_200_OK,
            )

        if not default_token_generator.check_token(user, token):
            return Response(
                {"detail": "Activation link is invalid or has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_active = True
        user.save(update_fields=["is_active"])
        return Response(
            {"detail": "Your account has been activated. You can now sign in."},
            status=status.HTTP_200_OK,
        )