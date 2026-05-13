from datetime import timezone

from django.contrib.auth.hashers import make_password
from django.shortcuts import render, get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError, PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from linkApp.emails import send_driver_kyc_pending_email, send_activation_email, send_account_admitted_email, \
    send_account_suspended_email, send_account_unsuspended_email, send_account_banned_email
from linkApp.jwt_utils import create_token_pair_for_user
from linkApp.models import UserAccount, KycSubmission
from linkApp.permissions import IsAdminRole, IsDriverRole
from linkApp.serializers import UserSerializer, UserCreateSerializer


# =============================================================================
# User ViewSet
# =============================================================================

class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """Full update of logged-in user's profile"""
        user = request.user
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            # Handle password hashing if updated
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        """Partial update of logged-in user's profile"""
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Allow logged-in user to delete their own account"""
        user = request.user
        user.delete()
        return Response({"message": "Account deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not current_password or not new_password:
            return Response(
                {"error": "Both current_password and new_password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not user.check_password(current_password):
            return Response(
                {"error": "Current password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)


class UserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'list': [IsAdminRole],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}
        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(
            response_dict,
            status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK
        )

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # All accounts start INACTIVE.
            #  - admin: activated via email link
            #  - driver : activated by admin after KYC approval
            user = serializer.save()
            user.is_active = False
            user.save(update_fields=["is_active"])

            response_payload = {"user_type": user.user_type}

            if user.user_type == UserAccount.UserTypes.DRIVER:
                send_driver_kyc_pending_email(user)
                response_payload["message"] = (
                    "Account created. Complete your KYC submission — "
                    "we'll email you once an admin reviews it."
                )
                # Issue short-lived tokens so the professional can submit KYC
                # while their account is still inactive.
                tokens = create_token_pair_for_user(user)
                response_payload["access"] = tokens["access"]
                response_payload["refresh"] = tokens["refresh"]
                response_payload["user"] = {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "phone": user.phone,
                    "user_type": user.user_type,
                }
            else:
                send_activation_email(user)
                response_payload["message"] = (
                    "Account created. Check your email for an activation link."
                )

            return Response(response_payload, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.user_type != "admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only update your own account.")

        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            # Handle password hashing if updated
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.user_type != "admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only update your own account.")

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            if "password" in serializer.validated_data:
                serializer.validated_data["password"] = make_password(serializer.validated_data["password"])
            serializer.save()
            return Response(serializer.data)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)

        # Permission check
        if request.user.user_type != "admin" and request.user.pk != user.pk:
            raise PermissionDenied("You can only delete your own account.")

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # --- Admin moderation actions on professionals ----------------------------
    def _ensure_admin(self, request):
            if request.user.user_type != "admin":
                raise PermissionDenied("Admins only.")

    @action(detail=True, methods=["post"], url_path="admit")
    def admit(self, request, pk=None):
        self._ensure_admin(request)
        user = get_object_or_404(UserAccount, pk=pk)
        user.is_active = True
        user.account_status = UserAccount.AccountStatus.ACTIVE
        user.save(update_fields=["is_active", "account_status"])
        kyc = KycSubmission.objects.filter(user=user).first()

        if kyc and kyc.status in (KycSubmission.Status.DRAFT, KycSubmission.Status.PENDING):
            kyc.status = KycSubmission.Status.APPROVED
            kyc.reviewed_by = request.user
            kyc.reviewed_at = timezone.now()
            kyc.save(update_fields=["status", "reviewed_by", "reviewed_at"])
        try:
            send_account_admitted_email(user)
        except Exception:
            pass
        return Response(UserSerializer(user).data)

    @action(detail=True, methods=["post"], url_path="suspend")
    def suspend(self, request, pk=None):
        self._ensure_admin(request)
        user = get_object_or_404(UserAccount, pk=pk)
        user.account_status = UserAccount.AccountStatus.SUSPENDED
        user.is_active = False
        notes = request.data.get("notes", "") or user.moderation_notes
        user.moderation_notes = notes
        user.save(update_fields=["account_status", "is_active", "moderation_notes"])

        try:
            send_account_suspended_email(user, notes=notes)
        except Exception:
            pass

        return Response(UserSerializer(user).data)

    @action(detail=True, methods=["post"], url_path="unsuspend")
    def unsuspend(self, request, pk=None):
        self._ensure_admin(request)
        user = get_object_or_404(UserAccount, pk=pk)
        user.account_status = UserAccount.AccountStatus.ACTIVE
        user.is_active = True
        user.save(update_fields=["account_status", "is_active"])
        try:
            send_account_unsuspended_email(user)
        except Exception:
            pass
        return Response(UserSerializer(user).data)

    @action(detail=True, methods=["post"], url_path="ban")
    def ban(self, request, pk=None):
        self._ensure_admin(request)
        user = get_object_or_404(UserAccount, pk=pk)
        user.account_status = UserAccount.AccountStatus.BANNED
        user.is_active = False
        notes = request.data.get("notes", "") or user.moderation_notes
        user.moderation_notes = notes
        user.save(update_fields=["account_status", "is_active", "moderation_notes"])
        # ---- NEW ----
        try:
            send_account_banned_email(user, notes=notes)
        except Exception:
            pass
        # -------------
        return Response(UserSerializer(user).data)

    @action(detail=True, methods=["post"], url_path="unban")
    def unban(self, request, pk=None):
        """Lift a ban on a user account, restoring access."""
        self._ensure_admin(request)
        user = get_object_or_404(UserAccount, pk=pk)
        user.account_status = UserAccount.AccountStatus.ACTIVE
        user.is_active = True
        user.save(update_fields=["account_status", "is_active"])
        try:
            # Reuse the unsuspended email template — same intent (access restored).
            send_account_unsuspended_email(user)
        except Exception:
            pass
        return Response(UserSerializer(user).data)
