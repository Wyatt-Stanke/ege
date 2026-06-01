"""TLS certificate generation and SSLContext setup with MemoryBIO helpers."""
import ipaddress
import logging
import ssl
from pathlib import Path

logger = logging.getLogger(__name__)

# Module-level SNI capture: servername_callback fires during handshake.
# Key: id(sslobj), value: SNI string
_sni_map: dict[int, str] = {}


def _sni_callback(ssl_obj, server_name: str, orig_ctx) -> None:  # noqa: ARG001
    if server_name:
        _sni_map[id(ssl_obj)] = server_name


def pop_sni(sslobj) -> str | None:
    """Retrieve (and remove) the SNI captured during handshake for this SSLObject."""
    return _sni_map.pop(id(sslobj), None)


# ------------------------------------------------------------------
# Certificate generation
# ------------------------------------------------------------------

def ensure_cert(cert_dir: Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path), generating them if absent."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    logger.info("Generating self-signed certificate in %s …", cert_dir)

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("capture.localhost"),
        x509.DNSName("api.localhost"),
        x509.DNSName("cdn.localhost"),
        x509.DNSName("ws.localhost"),
        x509.DNSName("*.test"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(
        f"\n[capture-server] Self-signed cert generated: {cert_path}\n"
        "  Trust it in your OS/browser trust store, or launch Chromium with\n"
        "  --ignore-certificate-errors for testing.\n"
    )
    return cert_path, key_path


# ------------------------------------------------------------------
# SSLContext
# ------------------------------------------------------------------

def build_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.options |= ssl.OP_NO_TICKET
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.set_servername_callback(_sni_callback)
    return ctx
