import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

import streamlit as st
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

APP_VERSION = 1
AAD = b"ardan-secure-text:v1"
MAX_TEXT_BYTES = 1_000_000
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)


def derive_kek(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Kata sandi wajib diisi.")
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
        password.encode("utf-8")
    )


def encrypt_text(plaintext: str, password: str) -> str:
    raw = plaintext.encode("utf-8")
    if not raw:
        raise ValueError("Teks atau link wajib diisi.")
    if len(raw) > MAX_TEXT_BYTES:
        raise ValueError("Input terlalu besar. Maksimum 1 MB.")

    # Kunci data selalu dinamis: DEK baru dibuat untuk setiap proses enkripsi.
    dek = AESGCM.generate_key(bit_length=256)
    data_nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(data_nonce, raw, AAD)

    # Kata sandi membentuk KEK untuk membungkus DEK (envelope encryption).
    salt = os.urandom(16)
    kek = derive_kek(password, salt)
    wrap_nonce = os.urandom(12)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, AAD)

    package = {
        "v": APP_VERSION,
        "alg": "AES-256-GCM",
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": b64e(salt),
        "wn": b64e(wrap_nonce),
        "wk": b64e(wrapped_dek),
        "dn": b64e(data_nonce),
        "ct": b64e(ciphertext),
    }
    compact = json.dumps(package, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "AST1." + b64e(compact)


def parse_package(token: str) -> dict[str, Any]:
    clean = token.strip()
    if not clean.startswith("AST1."):
        raise ValueError("Format ciphertext tidak dikenali.")
    try:
        package = json.loads(b64d(clean[5:]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Ciphertext tidak valid atau rusak.") from exc

    required = {"v", "alg", "kdf", "n", "r", "p", "salt", "wn", "wk", "dn", "ct"}
    if not isinstance(package, dict) or not required.issubset(package):
        raise ValueError("Struktur ciphertext tidak lengkap.")
    if package["v"] != APP_VERSION or package["alg"] != "AES-256-GCM" or package["kdf"] != "scrypt":
        raise ValueError("Versi atau algoritma ciphertext tidak didukung.")
    if (package["n"], package["r"], package["p"]) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise ValueError("Parameter keamanan ciphertext tidak didukung.")
    return package


def decrypt_text(token: str, password: str) -> str:
    package = parse_package(token)
    try:
        salt = b64d(package["salt"])
        wrap_nonce = b64d(package["wn"])
        wrapped_dek = b64d(package["wk"])
        data_nonce = b64d(package["dn"])
        ciphertext = b64d(package["ct"])
        if len(salt) != 16 or len(wrap_nonce) != 12 or len(data_nonce) != 12:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Komponen ciphertext tidak valid.") from exc

    try:
        kek = derive_kek(password, salt)
        dek = AESGCM(kek).decrypt(wrap_nonce, wrapped_dek, AAD)
        plaintext = AESGCM(dek).decrypt(data_nonce, ciphertext, AAD)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        # Pesan sengaja dibuat seragam agar tidak membocorkan detail kegagalan.
        raise ValueError("Kata sandi salah atau ciphertext telah dimodifikasi.")


def read_server_secret(name: str) -> str:
    value = os.getenv(name, "")
    if value:
        return value
    try:
        return str(st.secrets.get(name, ""))
    except FileNotFoundError:
        return ""


def secret_gate() -> bool:
    """Validasi dilakukan di backend. Secret asli tidak pernah dikirim ke browser."""
    configured_hash = read_server_secret("SECRET_ACCESS_SHA256").strip().lower()
    if not configured_hash:
        return False

    with st.expander("Akses generator rahasia", expanded=False):
        st.caption("Masukkan kode akses server. Tombol saja bukan autentikasi.")
        access_code = st.text_input("Kode akses", type="password", key="secret_access_code")
        if st.button("Buka generator", type="secondary", use_container_width=True):
            candidate = hashlib.sha256(access_code.encode("utf-8")).hexdigest()
            if access_code and hmac.compare_digest(candidate, configured_hash):
                st.session_state.secret_until = time.time() + 900
                st.success("Akses aktif selama 15 menit pada sesi ini.")
            else:
                time.sleep(0.4)
                st.error("Kode akses tidak valid.")
    return time.time() < st.session_state.get("secret_until", 0)


st.set_page_config(page_title="Secure Text", page_icon="🔐", layout="centered")
st.title("Secure Text")
st.caption("Enkripsi dan dekripsi teks atau link menggunakan AES-256-GCM.")

with st.sidebar:
    st.subheader("Keamanan")
    st.write("Kunci data dibuat ulang secara acak pada setiap enkripsi. Kata sandi tidak disimpan.")
    st.warning("Jika kata sandi hilang, data tidak dapat dipulihkan.")
    secret_enabled = bool(read_server_secret("SECRET_ACCESS_SHA256"))
    if secret_enabled:
        unlocked = secret_gate()
    else:
        unlocked = True
        st.info("Mode akses rahasia belum dikonfigurasi. Generator tersedia secara normal.")

mode = st.radio("Mode", ["Generator", "Translator"], horizontal=True)

if mode == "Generator":
    if not unlocked:
        st.info("Generator dikunci. Buka akses melalui panel di sebelah kiri.")
        st.stop()

    with st.form("encrypt_form", clear_on_submit=False):
        plaintext = st.text_area(
            "Teks atau link",
            placeholder="Contoh: www.google.com",
            height=140,
            max_chars=MAX_TEXT_BYTES,
        )
        password = st.text_input("Kata sandi", type="password", placeholder="Contoh: BurungPipit")
        password_repeat = st.text_input("Ulangi kata sandi", type="password")
        submitted = st.form_submit_button("Enkripsi", type="primary", use_container_width=True)

    if submitted:
        if password != password_repeat:
            st.error("Konfirmasi kata sandi tidak sama.")
        elif len(password) < 8:
            st.error("Kata sandi minimal 8 karakter.")
        else:
            try:
                result = encrypt_text(plaintext, password)
                st.session_state.last_ciphertext = result
                st.success("Enkripsi berhasil.")
            except ValueError as exc:
                st.error(str(exc))

    if st.session_state.get("last_ciphertext"):
        st.text_area(
            "Hasil enkripsi",
            value=st.session_state.last_ciphertext,
            height=220,
            key="ciphertext_output",
        )
        st.download_button(
            "Unduh ciphertext",
            data=st.session_state.last_ciphertext.encode("utf-8"),
            file_name="ciphertext.ast1.txt",
            mime="text/plain",
            use_container_width=True,
        )

else:
    st.info("Istilah yang tepat adalah dekripsi, bukan menerjemahkan hash. Hash tidak dapat dibalik.")
    with st.form("decrypt_form", clear_on_submit=False):
        ciphertext_input = st.text_area(
            "Hasil enkripsi",
            placeholder="Tempel nilai yang diawali AST1.",
            height=220,
        )
        decrypt_password = st.text_input("Kata sandi", type="password", key="decrypt_password")
        decrypt_submitted = st.form_submit_button("Dekripsi", type="primary", use_container_width=True)

    if decrypt_submitted:
        try:
            plaintext_result = decrypt_text(ciphertext_input, decrypt_password)
            st.session_state.last_plaintext = plaintext_result
            st.success("Dekripsi berhasil.")
        except ValueError as exc:
            st.session_state.pop("last_plaintext", None)
            st.error(str(exc))

    if st.session_state.get("last_plaintext") is not None:
        st.text_area(
            "Hasil asli",
            value=st.session_state.last_plaintext,
            height=140,
            key="plaintext_output",
        )
