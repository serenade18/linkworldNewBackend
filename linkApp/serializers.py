from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
from rest_framework_simplejwt.views import TokenObtainPairView

from linkApp.jwt_utils import create_token_pair_for_user
from linkApp.models import KycSubmission
from django.utils.text import slugify
import re

User = get_user_model()

# =============================================================================
# User Serializer
# =============================================================================

class CustomTokenObtainPairSerializer(serializers.Serializer):
    email = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = (attrs.get("email") or "").strip().lower()
        password = attrs.get("password")

        # Look the user up directly so we can distinguish "wrong password" from
        # "account is inactive" — Django's authenticate() returns None for both.
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid credentials")

        if getattr(user, "account_status", "active") == "suspended":
            raise serializers.ValidationError(
                "Your account has been suspended. Contact support."
            )
        if getattr(user, "account_status", "active") == "banned":
            raise serializers.ValidationError(
                "Your account has been banned."
            )
        if not user.is_active:
            # Professionals: surface the KYC state so the UI can route them
            # to the pending page.
            if user.user_type == "driver":
                kyc = getattr(user, "kyc", None)
                if kyc is None:
                    tokens = create_token_pair_for_user(user)
                    return {
                        "detail": "Your account is not active. Please complete your KYC submission.",
                        "account_status": "kyc_missing",
                        "user_type": "driver",
                        "access": tokens["access"],
                        "refresh": tokens["refresh"],
                        "user": {
                            "id": user.id,
                            "email": user.email,
                            "name": user.name,
                            "phone": user.phone,
                            "user_type": user.user_type,
                        },
                    }
                if kyc.status == KycSubmission.Status.REJECTED:
                    return {
                        "detail": "Your KYC was rejected." + (
                            f" Reason: {kyc.reviewer_notes}" if kyc.reviewer_notes else ""
                        ),
                        "account_status": "kyc_rejected",
                        "reviewer_notes": kyc.reviewer_notes or "",
                        "user_type": "driver",
                    }
                # Draft — KYC saved but onboarding payment not completed.
                # Return tokens so the UI can resume at the payment step
                # instead of forcing the pro to redo the whole form.
                if kyc.status == KycSubmission.Status.DRAFT:
                    tokens = create_token_pair_for_user(user)
                    return {
                        "detail": "Finish your onboarding payment to activate your account.",
                        "account_status": "kyc_draft",
                        "user_type": "driver",
                        "access": tokens["access"],
                        "refresh": tokens["refresh"],
                        "user": {
                            "id": user.id,
                            "email": user.email,
                            "name": user.name,
                            "phone": user.phone,
                            "user_type": user.user_type,
                        },
                    }
                # Pending (default)
                return {
                    "detail": "Your KYC is pending admin approval. You'll be notified by email.",
                    "account_status": "kyc_pending",
                    "user_type": "driver",
                }

            return {
                "detail": "Account not active. Please check your email for the activation link.",
                "account_status": "inactive",
                "user_type": user.user_type,
            }

        tokens = create_token_pair_for_user(user)

        return {
            "refresh": tokens["refresh"],
            "access": tokens["access"],
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "phone": user.phone,
                "user_type": user.user_type,
            }
        }


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        user = User.objects.create(**validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user


class UserCreateSerializer(serializers.ModelSerializer):
    user_type = serializers.ChoiceField(
        choices=User.UserTypes.choices,
        required=False,
        default=User.UserTypes.PATIENT
    )

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "name",
            "phone",
            "user_type",
            "password",
        ]
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def validate_user_type(self, value):
        valid_types = [choice[0] for choice in User.UserTypes.choices]

        if value not in valid_types:
            raise serializers.ValidationError(
                f"Invalid user type. Allowed: {', '.join(valid_types)}"
            )

        return value

    def create(self, validated_data):
        password = validated_data.pop("password")

        user = User.objects.create_user(
            email=validated_data["email"],
            name=validated_data["name"],
            phone=validated_data["phone"],
            password=password,
            user_type=validated_data.get(
                "user_type",
                User.UserTypes.PATIENT
            )
        )

        user.save()

        return user


class CustomUserSerializer(serializers.ModelSerializer):
    last_login = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S",
        read_only=True
    )

    user_type_display = serializers.CharField(
        source="get_user_type_display",
        read_only=True
    )

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "name",
            "phone",
            "user_type",
            "user_type_display",
            "last_login",
        ]


# =============================================================================
# KYC Serializers
# =============================================================================

class KycSubmissionSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(
        source="user.email", read_only=True)
    user_name = serializers.CharField(
        source="user.name", read_only=True)
    user_phone = serializers.CharField(
        source="user.phone", read_only=True)
    reviewed_by_email = serializers.CharField(
        source="reviewed_by.email", read_only=True, default=None)
    vehicle_type_display = serializers.CharField(
        source="get_vehicle_type_display", read_only=True)
    status_display = serializers.CharField(
        source="get_status_display", read_only=True)

    class Meta:
        model = KycSubmission
        fields = [
            "id",
            "user",
            "user_email",
            "user_name",
            "user_phone",
            "full_name",
            "contact_email",
            "contact_phone",
            "national_id",
            "date_of_birth",
            "address",
            "vehicle_type",
            "vehicle_type_display",
            "vehicle_make",
            "vehicle_model",
            "vehicle_color",
            "vehicle_year",
            "license_plate",
            "id_doc",
            "license_doc",
            "vehicle_photo",
            "profile_photo",
            "insurance_doc",
            "status",
            "status_display",
            "reviewer_notes",
            "reviewed_by",
            "reviewed_by_email",
            "reviewed_at",
            "onboarding_paid",
            "onboarding_reference",
            "submitted_at",
            "updated_at",
        ]

        read_only_fields = [
            "user",
            "status",
            "status_display",
            "reviewer_notes",
            "reviewed_by",
            "reviewed_by_email",
            "reviewed_at",
            "submitted_at",
            "updated_at",
        ]

    def to_internal_value(self, data):
        data = _coerce_kyc_formdata(data)
        return super().to_internal_value(data)

    def validate_license_plate(self, value):
        return value.strip().upper()

    def validate_contact_email(self, value):
        return value.strip().lower()

    def create(self, validated_data):
        request = self.context.get("request")

        if request and request.user.is_authenticated:
            validated_data["user"] = request.user

        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Prevent changing approved KYC unless admin resets it
        if instance.status == KycSubmission.Status.APPROVED:
            raise serializers.ValidationError(
                "Approved KYC submissions cannot be modified."
            )

        return super().update(instance, validated_data)


def _coerce_kyc_formdata(data):
    """
    Convert FormData/QueryDict into proper Python values before DRF validation.
    Preserves uploaded files and normalizes values.
    """
    if hasattr(data, "lists"):
        out = {}

        for key, value in data.lists():
            out[key] = value[0] if len(value) == 1 else value
    else:
        out = dict(data)

    # Normalize booleans
    boolean_fields = [
        "onboarding_paid",
    ]

    for field in boolean_fields:
        value = out.get(field)

        if isinstance(value, str):
            low = value.strip().lower()

            if low in ("true", "1", "yes"):
                out[field] = True

            elif low in ("false", "0", "no"):
                out[field] = False

    # Normalize text fields
    if out.get("license_plate"):
        out["license_plate"] = (
            str(out["license_plate"])
            .strip()
            .upper()
        )

    if out.get("contact_email"):
        out["contact_email"] = (
            str(out["contact_email"])
            .strip()
            .lower()
        )

    return out


class KycReviewSerializer(serializers.Serializer):
    """
    Used by admin approve/reject actions.
    """
    notes = serializers.CharField(required=False, allow_blank=True, default="")


