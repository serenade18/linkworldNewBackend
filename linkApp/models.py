from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

from linkProject import settings


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
        DRAFT = "draft", "Draft"            # saved by driver, awaiting payment
        PENDING = "pending", "Pending"      # paid, awaiting admin review
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    class Vehicle(models.TextChoices):
        BODA = "boda", "Boda"
        BICYCLE = "bicycle", "Bicycle"
        VAN = "van", "Van"
        TRUCK = "truck", "Truck"
        CAR = "car", "Car"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="kyc",
    )
    full_name = models.CharField(max_length=255)
    contact_email = models.EmailField()
    contact_phone = models.CharField(max_length=20)
    national_id = models.CharField(max_length=100, unique=True)
    date_of_birth = models.DateField(null=True, blank=True)
    address = models.TextField(blank=True)
    vehicle_type = models.CharField(max_length=20, choices=Vehicle.choices)
    vehicle_make = models.CharField(max_length=100, blank=True)
    vehicle_model = models.CharField(max_length=100, blank=True)
    vehicle_color = models.CharField(max_length=50, blank=True)
    vehicle_year = models.PositiveIntegerField(null=True, blank=True)
    license_plate = models.CharField(max_length=50, unique=True)
    id_doc = models.FileField(
        upload_to="kyc/id_docs/"
    )
    license_doc = models.FileField(
        upload_to="kyc/license_docs/"
    )
    vehicle_photo = models.ImageField(
        upload_to="kyc/vehicle_photos/",
        null=True,
        blank=True
    )
    profile_photo = models.ImageField(
        upload_to="kyc/profile_photos/"
    )
    insurance_doc = models.FileField(
        upload_to="kyc/insurance_docs/",
        null=True,
        blank=True
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.DRAFT
    )
    reviewer_notes = models.TextField(
        blank=True
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_kycs"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    onboarding_paid = models.BooleanField(default=False)
    onboarding_reference = models.CharField(max_length=255, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-submitted_at"]
        verbose_name = "KYC Submission"
        verbose_name_plural = "KYC Submissions"

    def __str__(self):
        return f"{self.full_name} - {self.status}"

    @property
    def is_approved(self):
        return self.status == self.Status.APPROVED

    @property
    def is_pending(self):
        return self.status == self.Status.PENDING

    @property
    def is_rejected(self):
        return self.status == self.Status.REJECTED

