"""Password reset endpoints.

Flow:
  POST /api/password-reset/         { email }                   -> sends email
  POST /api/password-reset/confirm/ { token, new_password }     -> sets password

The `token` returned in the email is a single opaque string of the form
"<uidb64>:<token>" so the frontend only has to round-trip one value.
"""
from __future__ import annotations

import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from linkApp.emails import _send, _wrap, _button

User = get_user_model()
logger = logging.getLogger(__name__)


def _build_reset_url(user) -> str:
    frontend = getattr(settings, "FRONTEND_URL", "http://localhost:8080").rstrip("/")
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    return f"{frontend}/reset-password?token={uid}:{token}"


def _send_password_reset_email(user) -> None:
    url = _build_reset_url(user)
    name = (user.name or "there").strip()
    text = (
        f"Hello {name},\n\n"
        "We received a request to reset your Linkworld password. "
        f"Visit the link below to choose a new password:\n{url}\n\n"
        "If you didn't request this, you can ignore this email — your "
        "password will stay the same."
    )
    html = _wrap(
        title="Reset your password",
        body_html=(
            f"<p>Hello {name}, we received a request to reset the password "
            "for your Linkworld account.</p>"
            "<p>Click the button below to choose a new password. This link "
            "will expire shortly for your security.</p>"
            "<p>If you didn't request this, you can safely ignore this email.</p>"
        ),
        cta_html=_button("Reset my password", url),
    )
    _send("Reset your Linkworld password", user.email, text, html)


class PasswordResetRequestView(APIView):
    """POST { email } -> always returns 200 to avoid leaking which emails exist."""

    permission_classes = [AllowAny]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        if not email:
            return Response(
                {"error": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            user = None

        if user is not None:
            try:
                _send_password_reset_email(user)
            except Exception:  # noqa: BLE001
                logger.exception("Failed to send password reset email to %s", email)

        return Response(
            {
                "message": (
                    "If an account exists for that email, a reset link has "
                    "been sent."
                )
            },
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(APIView):
    """POST { token, new_password } -> sets new password if token is valid."""

    permission_classes = [AllowAny]

    def post(self, request):
        token_value = (request.data.get("token") or "").strip()
        new_password = request.data.get("new_password") or ""

        if not token_value or not new_password:
            return Response(
                {"error": "Both token and new_password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if ":" not in token_value:
            return Response(
                {"error": "Reset link is invalid or has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uidb64, token = token_value.split(":", 1)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Reset link is invalid or has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not default_token_generator.check_token(user, token):
            return Response(
                {"error": "Reset link is invalid or has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as exc:
            return Response(
                {"error": " ".join(exc.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save(update_fields=["password"])

        return Response(
            {"message": "Your password has been reset. You can now sign in."},
            status=status.HTTP_200_OK,
        )
