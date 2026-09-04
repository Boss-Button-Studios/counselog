"""Envelope encryption, unlock factors, and in-memory key custody.

Nothing here may assume it is running on the laptop, or that a YubiKey exists —
the desktop imports this too. See CLAUDE.md.
"""

from core.crypto.envelope import (
    DEK_BYTES,
    KEYRING_VERSION,
    Keyring,
    KeyringError,
    LastWrapperError,
    UnlockFailed,
    Wrapper,
    new_dek,
)
from core.crypto.factors import (
    FactorError,
    FactorUnavailable,
    KeyFactor,
    PasswordFactor,
    YubiKeyFactor,
)
from core.crypto.session import DekSession, SessionClosed, SessionExpired
from core.crypto.signing import (
    ALGORITHM,
    PivSigner,
    Signer,
    SignerUnavailable,
    SigningError,
    SoftwareSigner,
    key_id,
    signed_bytes,
    verify_signature,
)

__all__ = [
    "ALGORITHM",
    "DEK_BYTES",
    "KEYRING_VERSION",
    "DekSession",
    "FactorError",
    "FactorUnavailable",
    "KeyFactor",
    "Keyring",
    "KeyringError",
    "LastWrapperError",
    "PasswordFactor",
    "PivSigner",
    "SessionClosed",
    "SessionExpired",
    "Signer",
    "SignerUnavailable",
    "SigningError",
    "SoftwareSigner",
    "UnlockFailed",
    "Wrapper",
    "YubiKeyFactor",
    "key_id",
    "new_dek",
    "signed_bytes",
    "verify_signature",
]
