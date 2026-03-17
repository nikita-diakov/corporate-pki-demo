import base64
import hashlib
import json
import os
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, lib
from pkcs11.constants import CertificateType

APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
STATE_DIR = ROOT_DIR / "state"

TEMPLATES = Jinja2Templates(directory=str(APP_DIR / "templates"))

# Default lab parameters
TOKEN_LABEL = os.getenv("TOKEN_LABEL", "TestToken")
TOKEN_PIN = os.getenv("TOKEN_PIN", "1234")
KEY_LABEL = os.getenv("KEY_LABEL", "signKey")
CERT_LABEL = os.getenv("CERT_LABEL", "signCert")

SOFTHSM2_CONF = os.getenv("SOFTHSM2_CONF", str(ROOT_DIR / "conf" / "softhsm2.conf"))
SOFTHSM_MODULE = os.getenv("SOFTHSM_MODULE", "")

CA_KEY_PATH = STATE_DIR / "ca_key.pem"
CA_CERT_PATH = STATE_DIR / "ca_cert.pem"
KEY_ID_PATH = STATE_DIR / "key_id.hex"
REVOKED_PATH = STATE_DIR / "revoked.json"

# ASN.1 DigestInfo prefix for SHA-256 (PKCS#1 v1.5)
SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

app = FastAPI(title="corporate-pki-demo", version="1.0")

@app.exception_handler(Exception)
async def _all_exception_handler(request, exc):
    tb = traceback.format_exc()
    print(tb)
    tb_short = "\n".join(tb.splitlines()[-80:])
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {exc!r}", "traceback": tb_short},
    )

static_dir = APP_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _format_dt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _nvb(cert: x509.Certificate) -> datetime:
    """not_valid_before as UTC-aware datetime"""
    dt = getattr(cert, "not_valid_before_utc", None)
    if dt is None:
        dt = cert.not_valid_before
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _nva(cert: x509.Certificate) -> datetime:
    """not_valid_after as UTC-aware datetime"""
    dt = getattr(cert, "not_valid_after_utc", None)
    if dt is None:
        dt = cert.not_valid_after
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _detect_module_path() -> str:
    if SOFTHSM_MODULE and Path(SOFTHSM_MODULE).exists():
        return SOFTHSM_MODULE
    candidates = [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    for p in candidates:
        if Path(p).exists():
            return p
    return ""


def _pkcs11_token():
    module_path = _detect_module_path()
    if not module_path:
        raise RuntimeError("libsofthsm2.so not found. Install softhsm2 or set SOFTHSM_MODULE.")
    os.environ["SOFTHSM2_CONF"] = SOFTHSM2_CONF
    pkcs11 = lib(module_path)
    token = pkcs11.get_token(token_label=TOKEN_LABEL)
    return pkcs11, token, module_path


def _load_or_create_ca():
    _ensure_state_dir()
    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        ca_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        return ca_key, ca_cert

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "corporate-pki-demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "corporate-pki-demo Root CA"),
    ])
    now = _now_utc()
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_key, ca_cert


def _load_revoked() -> set[str]:
    _ensure_state_dir()
    if not REVOKED_PATH.exists():
        return set()
    try:
        data = json.loads(REVOKED_PATH.read_text(encoding="utf-8"))
        return set(data.get("revoked_serials", []))
    except Exception:
        return set()


def _save_revoked(serials: set[str]):
    _ensure_state_dir()
    REVOKED_PATH.write_text(
        json.dumps({"revoked_serials": sorted(serials)}, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def _get_key_id() -> Optional[bytes]:
    if not KEY_ID_PATH.exists():
        return None
    hexstr = KEY_ID_PATH.read_text(encoding="utf-8").strip()
    if not hexstr:
        return None
    return bytes.fromhex(hexstr)


def _set_key_id(key_id: bytes):
    _ensure_state_dir()
    KEY_ID_PATH.write_text(key_id.hex(), encoding="utf-8")


def _ensure_keypair(session):
    """Ensure RSA keypair exists in token, return (pub, priv, key_id)."""
    key_id = _get_key_id()
    priv = pub = None

    if key_id:
        try:
            priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=KEY_LABEL, id=key_id)
            pub = session.get_key(object_class=ObjectClass.PUBLIC_KEY, label=KEY_LABEL, id=key_id)
        except Exception:
            priv = pub = None

    if priv is None or pub is None:
        try:
            priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=KEY_LABEL)
            pub = session.get_key(object_class=ObjectClass.PUBLIC_KEY, label=KEY_LABEL)
            try:
                kid = priv[Attribute.ID]
                if isinstance(kid, (bytes, bytearray)) and kid:
                    key_id = bytes(kid)
                    _set_key_id(key_id)
            except Exception:
                pass
        except Exception:
            priv = pub = None

    if priv is None or pub is None:
        key_id = os.urandom(16)
        pub, priv = session.generate_keypair(
            KeyType.RSA, 2048,
            store=True,
            label=KEY_LABEL,
            id=key_id,
            public_template={Attribute.VERIFY: True},
            private_template={
                Attribute.SIGN: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )
        _set_key_id(key_id)

    return pub, priv, key_id


def _issue_signer_cert(cn: str, days: int) -> x509.Certificate:
    ca_key, ca_cert = _load_or_create_ca()
    _pkcs11, token, _module_path = _pkcs11_token()

    with token.open(user_pin=TOKEN_PIN, rw=True) as session:
        pub, _priv, key_id = _ensure_keypair(session)

        # Re-issue policy: remove old signer cert so CN changes apply
        try:
            search = {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: CERT_LABEL}
            if key_id:
                search[Attribute.ID] = key_id
            for obj in session.get_objects(search):
                try:
                    obj.destroy()
                except Exception:
                    pass
        except Exception:
            pass

        modulus = int.from_bytes(pub[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub[Attribute.PUBLIC_EXPONENT], "big")
        pub_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()

        now = _now_utc()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "corporate-pki-demo"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=False,
                    key_agreement=False,
                    content_commitment=True,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                    crl_sign=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )

        cert_der = cert.public_bytes(serialization.Encoding.DER)
        subject_der = cert.subject.public_bytes(serialization.Encoding.DER)
        issuer_der = cert.issuer.public_bytes(serialization.Encoding.DER)
        serial_bytes = cert.serial_number.to_bytes(
            max(1, (cert.serial_number.bit_length() + 7) // 8),
            "big"
        )

        session.create_object({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
            Attribute.LABEL: CERT_LABEL,
            Attribute.ID: key_id,
            Attribute.TOKEN: True,
            Attribute.VALUE: cert_der,
            Attribute.SUBJECT: subject_der,
            Attribute.ISSUER: issuer_der,
            Attribute.SERIAL_NUMBER: serial_bytes,
        })

        # Read back (by ID) to ensure we return the stored object
        search = {Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: CERT_LABEL, Attribute.ID: key_id}
        cert_obj = next(session.get_objects(search))
        cert_der2 = cert_obj[Attribute.VALUE]
        return x509.load_der_x509_certificate(cert_der2)


def _read_signer_cert_from_token() -> Optional[x509.Certificate]:
    try:
        _pkcs11, token, _module_path = _pkcs11_token()
        with token.open(user_pin=TOKEN_PIN) as session:
            cert_obj = next(session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.LABEL: CERT_LABEL,
            }))
            cert_der = cert_obj[Attribute.VALUE]
            return x509.load_der_x509_certificate(cert_der)
    except Exception:
        return None


def _sign_with_token(data: bytes) -> bytes:
    digest = hashlib.sha256(data).digest()
    digestinfo = SHA256_DIGESTINFO_PREFIX + digest

    _pkcs11, token, _module_path = _pkcs11_token()
    key_id = _get_key_id()

    # IMPORTANT: key handles are valid only while the session is open
    with token.open(user_pin=TOKEN_PIN, rw=True) as session:
        priv = None
        if key_id:
            try:
                priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=KEY_LABEL, id=key_id)
            except Exception:
                priv = None
        if priv is None:
            priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=KEY_LABEL)

        return priv.sign(digestinfo, mechanism=Mechanism.RSA_PKCS)


def _validate_cert_chain(cert: x509.Certificate) -> tuple[bool, str]:
    _ca_key, ca_cert = _load_or_create_ca()
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False, "Certificate signature check failed (not issued by this CA or corrupted)."

    now = _now_utc()
    if now < _nvb(cert):
        return False, "Certificate is not valid yet (not_valid_before)."
    if now > _nva(cert):
        return False, "Certificate has expired (not_valid_after)."

    return True, "Trust chain OK (validated against local Root CA)."


@app.get("/", response_class=HTMLResponse)
def ui(request: Request):
    return TEMPLATES.TemplateResponse("index.html", {"request": request})


@app.get("/api/status")
def status():
    st = {
        "token": {"ok": False, "label": TOKEN_LABEL, "module": None, "conf": SOFTHSM2_CONF},
        "signer": {"ready": False, "key_present": False, "cert_present": False, "not_after": None, "revoked": False},
        "ca": {"ready": False, "subject": None, "not_after": None},
    }

    # CA status
    try:
        _ca_key, ca_cert = _load_or_create_ca()
        st["ca"]["ready"] = True
        st["ca"]["subject"] = ca_cert.subject.rfc4514_string()
        st["ca"]["not_after"] = _format_dt(_nva(ca_cert))
    except Exception:
        pass

    # Token status
    try:
        _pkcs11, token, module_path = _pkcs11_token()
        st["token"]["ok"] = True
        st["token"]["module"] = module_path

        with token.open(user_pin=TOKEN_PIN) as session:
            try:
                _ = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label=KEY_LABEL)
                st["signer"]["key_present"] = True
            except Exception:
                st["signer"]["key_present"] = False

        cert = _read_signer_cert_from_token()
        if cert:
            st["signer"]["cert_present"] = True
            st["signer"]["not_after"] = _format_dt(_nva(cert))
            serial = format(cert.serial_number, "x")
            st["signer"]["revoked"] = serial in _load_revoked()

        st["signer"]["ready"] = st["signer"]["key_present"] and st["signer"]["cert_present"]
    except Exception:
        st["token"]["ok"] = False
        st["token"]["module"] = _detect_module_path() or None

    return st


@app.post("/api/enroll")
def enroll(payload: dict):
    cn = str(payload.get("cn", "")).strip()
    days = int(payload.get("days", 365))
    if not cn:
        raise HTTPException(400, detail="CN is required.")
    if days < 1 or days > 3650:
        raise HTTPException(400, detail="Validity (days) must be between 1 and 3650.")

    cert = _issue_signer_cert(cn=cn, days=days)
    serial_hex = format(cert.serial_number, "x")
    _ensure_state_dir()
    (STATE_DIR / "signer_cert.pem").write_text(
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        encoding="utf-8",
    )
    return {
        "serial": serial_hex,
        "not_after": _format_dt(_nva(cert)),
        "cert_url": "/api/cert/signer_cert.pem",
    }


@app.get("/api/cert/signer_cert.pem")
def download_signer_cert():
    p = STATE_DIR / "signer_cert.pem"
    if not p.exists():
        raise HTTPException(404, detail="Signer certificate not found. Run Enroll first.")
    return FileResponse(str(p), media_type="application/x-pem-file", filename="signer_cert.pem")


@app.get("/api/ca/ca_cert.pem")
def download_ca_cert():
    _load_or_create_ca()
    return FileResponse(str(CA_CERT_PATH), media_type="application/x-pem-file", filename="ca_cert.pem")


@app.post("/api/sign")
async def sign(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(400, detail="Empty file.")

    cert = _read_signer_cert_from_token()
    if not cert:
        raise HTTPException(400, detail="Signer certificate not found in token. Run Enroll first.")

    now = _now_utc()
    serial_hex = format(cert.serial_number, "x")
    if serial_hex in _load_revoked():
        raise HTTPException(400, detail="Signer certificate is revoked (demo policy blocks signing).")
    if now < _nvb(cert) or now > _nva(cert):
        raise HTTPException(400, detail="Signer certificate is not time-valid.")

    sig = _sign_with_token(data)

    sha256_hex = hashlib.sha256(data).hexdigest()
    sig_b64 = base64.b64encode(sig).decode("ascii")

    _ensure_state_dir()
    (STATE_DIR / "last_signature.b64").write_text(sig_b64, encoding="utf-8")
    (STATE_DIR / "signer_cert.pem").write_text(
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        encoding="utf-8",
    )

    return {
        "sha256_hex": sha256_hex,
        "signature_b64": sig_b64,
        "download_signature_url": "/api/signature/last_signature.b64",
        "cert_url": "/api/cert/signer_cert.pem",
    }


@app.get("/api/signature/last_signature.b64")
def download_last_signature():
    p = STATE_DIR / "last_signature.b64"
    if not p.exists():
        raise HTTPException(404, detail="No signature yet.")
    return FileResponse(str(p), media_type="text/plain", filename="signature.b64")


@app.post("/api/verify")
async def verify(file: UploadFile = File(...), signature_b64: str = Form(...)):
    data = await file.read()
    if not data:
        raise HTTPException(400, detail="Empty file.")

    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except Exception:
        raise HTTPException(400, detail="Signature must be a valid Base64 string.")

    cert = _read_signer_cert_from_token()
    if not cert:
        raise HTTPException(400, detail="Signer certificate not found in token. Run Enroll first.")

    serial_hex = format(cert.serial_number, "x")
    revoked = serial_hex in _load_revoked()

    cert_ok, cert_msg = _validate_cert_chain(cert)
    signature_ok = False
    sig_msg = ""

    try:
        cert.public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        signature_ok = True
        sig_msg = "Signature is mathematically correct."
    except Exception:
        signature_ok = False
        sig_msg = "Signature verification failed for this file/certificate."

    overall_ok = signature_ok and cert_ok and (not revoked)
    msg_lines = [sig_msg, cert_msg]
    if revoked:
        msg_lines.append("Certificate is revoked (demo revocation list).")

    return {
        "signature_ok": signature_ok,
        "cert_ok": cert_ok,
        "revoked": revoked,
        "overall_ok": overall_ok,
        "message": "\n".join(msg_lines),
        "cert_subject": cert.subject.rfc4514_string(),
        "cert_serial": serial_hex,
        "cert_not_after": _format_dt(_nva(cert)),
    }


@app.post("/api/revoke")
def revoke():
    cert = _read_signer_cert_from_token()
    if not cert:
        raise HTTPException(400, detail="Signer certificate not found.")
    serial_hex = format(cert.serial_number, "x")
    revoked = _load_revoked()
    revoked.add(serial_hex)
    _save_revoked(revoked)
    return {"ok": True, "revoked_serial": serial_hex}
