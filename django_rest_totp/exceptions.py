from rest_framework_simplejwt.exceptions import InvalidToken


class InvalidRefreshToken(InvalidToken):
    default_code = "refresh_token_not_valid"
