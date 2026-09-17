class CryptMasterError(Exception):
    """Base class for all client errors."""


class EnrollmentError(CryptMasterError):
    """Raised when server enrollment fails or is still pending."""


class SecretNotFoundError(CryptMasterError):
    """Raised when the vault has no matching secret."""


class VaultUnreachableError(CryptMasterError):
    """Raised after retries are exhausted trying to reach the vault."""
