from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.utils import get_md5_hash_password


def create_token_pair_for_user(user):
    """Create refresh/access tokens without SimpleJWT's inactive-user warning.

    We intentionally allow inactive professionals to authenticate only far enough
    to complete or review KYC-related flows.
    """

    user_id = getattr(user, api_settings.USER_ID_FIELD)
    if not isinstance(user_id, int):
        user_id = str(user_id)

    refresh = RefreshToken()
    refresh[api_settings.USER_ID_CLAIM] = user_id

    if getattr(api_settings, "CHECK_REVOKE_TOKEN", False):
        refresh[api_settings.REVOKE_TOKEN_CLAIM] = get_md5_hash_password(user.password)

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }