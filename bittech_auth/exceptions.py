class BittechAuthError(Exception):
    code = "BITTECH_AUTH_ERROR"
    
    def __init__(self, message: str = None) -> None:
        super().__init__(message or self.code)


class LicenseConfigError(BittechAuthError):
    code = "LICENSE_CONFIG_ERROR"


class LicenseNotFoundError(BittechAuthError):
    code = "LICENSE_NOT_FOUND"


class LicenseNotActiveError(BittechAuthError):
    code = "LICENSE_NOT_ACTIVE"


class ReplayAttackError(BittechAuthError):
    code = "REPLAY_ATTACK"


class AuthServiceRequestError(BittechAuthError):
    code = "AUTH_SERVICE_REQUEST_ERROR"
