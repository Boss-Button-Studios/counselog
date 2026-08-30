"""The private certificate authority that lets the two machines trust each other.

Mutual TLS, both directions. The desktop proves it is the desktop; the laptop
proves it is a device that has been enrolled. Neither trusts a public CA, and
nothing on the network can talk to the service without a certificate this CA
issued — which is what makes it safe to listen on a tailnet at all.

Spec §6 asks for this from v0 rather than retrofitted later, because the plan is
to extend capture to more devices. Each device therefore gets its *own* client
certificate rather than sharing one: enrolling a phone later, or revoking a lost
laptop, should not mean re-issuing everything.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from core import config

CA_VALID_DAYS = 3650
LEAF_VALID_DAYS = 825  # the common browser/TLS ceiling; no reason to exceed it
ORG = "Counselog"


class CertificateError(Exception):
    """Something is wrong with the certificate material."""


@dataclass(frozen=True)
class CertPaths:
    """Where the material lives. `certs/` is gitignored."""

    root: Path

    @property
    def ca_cert(self) -> Path:
        return self.root / "ca.crt"

    @property
    def ca_key(self) -> Path:
        return self.root / "ca.key"

    def cert(self, name: str) -> Path:
        return self.root / f"{name}.crt"

    def key(self, name: str) -> Path:
        return self.root / f"{name}.key"


def default_paths() -> CertPaths:
    """Where certificates live.

    COUNSELOG_CERTS overrides the location, which a device with an unusual
    layout may want, and which lets the tests run without writing into the repo.
    """
    override = os.environ.get("COUNSELOG_CERTS")
    if override:
        return CertPaths(Path(override).expanduser())
    return CertPaths(Path(__file__).resolve().parent.parent / "certs")


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    """Write a private key readable only by its owner.

    No passphrase: the service has to start unattended, and a passphrase it
    could read by itself protects nothing. The file permissions are the control.
    """
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(path, 0o644)


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _builder(subject: x509.Name, issuer: x509.Name, public_key, days: int):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        # Backdated slightly so a small clock difference between the two
        # machines does not make a freshly issued certificate "not yet valid".
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
    )


def create_ca(paths: CertPaths) -> None:
    """Create the authority both machines will trust."""
    paths.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name("Counselog Local CA")
    cert = (
        _builder(subject, subject, key.public_key(), CA_VALID_DAYS)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_key(paths.ca_key, key)
    _write_cert(paths.ca_cert, cert)


def _load_ca(paths: CertPaths) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    if not paths.ca_key.exists() or not paths.ca_cert.exists():
        raise CertificateError("No certificate authority yet. Run `counselog certs init`.")
    key = serialization.load_pem_private_key(paths.ca_key.read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate(paths.ca_cert.read_bytes())
    return key, cert  # type: ignore[return-value]


def issue_server(paths: CertPaths, hostnames: list[str], addresses: list[str]) -> None:
    """Issue the desktop's certificate.

    Every name and address the laptop might dial goes in, including loopback so
    the development mode works untouched. Mutual TLS is the real gate, so a
    generous SAN list costs nothing and removes a whole class of confusing
    handshake failures.
    """
    ca_key, ca_cert = _load_ca(paths)
    key = ec.generate_private_key(ec.SECP256R1())

    names: list[x509.GeneralName] = []
    for host in dict.fromkeys([*hostnames, *config.LOOPBACK_NAMES]):
        names.append(x509.DNSName(host))
    for address in dict.fromkeys([*addresses, *config.LOOPBACK_IPS]):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(address)))
        except ValueError as exc:
            raise CertificateError(f"{address!r} is not a valid IP address.") from exc

    cert = (
        _builder(_name("counselog-desktop"), ca_cert.subject, key.public_key(), LEAF_VALID_DAYS)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(paths.key("server"), key)
    _write_cert(paths.cert("server"), cert)


def issue_client(paths: CertPaths, device: str) -> None:
    """Issue one device's certificate.

    The common name identifies the device to the service, so it can say which
    machine connected. One per device, never shared — see the module docstring.
    """
    if not device.isidentifier() and not device.replace("-", "").isalnum():
        raise CertificateError(
            f"{device!r} is not a usable device name. Use letters, numbers and hyphens."
        )
    ca_key, ca_cert = _load_ca(paths)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        _builder(_name(device), ca_cert.subject, key.public_key(), LEAF_VALID_DAYS)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(paths.key(device), key)
    _write_cert(paths.cert(device), cert)


def server_context(paths: CertPaths) -> ssl.SSLContext:
    """TLS for the desktop, refusing anyone without a certificate from our CA."""
    _require(paths.cert("server"), paths.key("server"), paths.ca_cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(paths.cert("server"), paths.key("server"))
    context.load_verify_locations(paths.ca_cert)
    # The whole point: an unknown client on the tailnet is turned away at the
    # handshake, before it can send a single byte of a request.
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def client_context(paths: CertPaths, device: str) -> ssl.SSLContext:
    """TLS for a capture device, checking the desktop is really the desktop."""
    _require(paths.cert(device), paths.key(device), paths.ca_cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(paths.cert(device), paths.key(device))
    context.load_verify_locations(paths.ca_cert)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


def peer_name(peer_cert: dict | None) -> str:
    """Pull the device name out of a verified peer certificate.

    Only ever called on a certificate the TLS layer has already validated
    against our CA, so the name can be trusted to identify the device.
    """
    if not peer_cert:
        return "unknown"
    for field in peer_cert.get("subject", ()):
        for key, value in field:
            if key == "commonName":
                return value
    return "unknown"


def _require(*paths: Path) -> None:
    missing = [str(p.name) for p in paths if not p.exists()]
    if missing:
        raise CertificateError(
            f"Missing certificate files: {', '.join(missing)}. "
            "Run `counselog certs init` on the desktop, then copy the bundle across."
        )
