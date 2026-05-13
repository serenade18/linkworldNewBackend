from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

# ============================
# USER MODEL
# ============================

class UserAccountManager(BaseUserManager):
    def create_user(self, email, name, phone, password=None, user_type=None):
        if not email:
            raise ValueError("Users must have an email address")

        email = self.normalize_email(email).lower()

        user = self.model(
            email=email,
            name=name,
            phone=phone,
            user_type=user_type or UserAccount.UserTypes.CUSTOMER,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phone, password=None):
        user = self.create_user(
            email=email,
            name=name,
            phone=phone,
            password=password,
            user_type=UserAccount.UserTypes.ADMIN,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    class UserTypes(models.TextChoices):
        DRIVER = "driver", "Driver"
        ADMIN = "admin", "Admin"

    class AccountStatus(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        BANNED = "banned", "Banned"

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    user_type = models.CharField(
        max_length=20,
        choices=UserTypes.choices,
        default=UserTypes.DRIVER,
    )

    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    account_status = models.CharField(
        max_length=16,
        choices=AccountStatus.choices,
        default=AccountStatus.ACTIVE,
    )
    moderation_notes = models.TextField(blank=True, default="")
    added_on = models.DateTimeField(auto_now_add=True)

    objects = UserAccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "phone"]

    def __str__(self):
        return f"{self.email} ({self.user_type})"

# ============================
# KYC SUBMISSION (Professionals)
# ============================

def _kyc_upload_path(instance, filename):
    return f"kyc/{instance.user_id}/{filename}"


class KycSubmission(models.Model):
    class Status(models.TextChoices):
        DRAFT = "draft", "Draft"            # saved by pro, awaiting payment
        PENDING = "pending", "Pending"      # paid, awaiting admin review
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    user = models.OneToOneField(
        UserAccount,
        on_delete=models.CASCADE,
        related_name="kyc",
    )