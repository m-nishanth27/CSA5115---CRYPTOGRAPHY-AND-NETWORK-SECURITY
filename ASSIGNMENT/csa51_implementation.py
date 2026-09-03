"""
CSA51 - Cryptography and Network Security
Implementation of Strategy A, B, and C for the assignment:
"Evaluation and Design of an Integrated Public Key and Authentication
Security System"

Requires: pip install cryptography
"""

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import os

SEP = "\n" + "=" * 70 + "\n"

# ---------------------------------------------------------------------
# STRATEGY A: RSA Encryption + Public/Private Key Pair
# ---------------------------------------------------------------------
def strategy_a():
    print(SEP + "STRATEGY A - Conventional Public Key Security (RSA only)" + SEP)

    # 1. Key generation
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    print("[Key Generation] 2048-bit RSA key pair generated.")

    # 2. Message to protect
    message = b"TXN: Acc4471 -> Acc9902; Amount=250000.00; Ref=INV20981"
    print(f"[Original Message] {message.decode()}")

    # 3. Encryption with receiver's public key
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    print(f"[Ciphertext] {ciphertext.hex()[:64]}... ({len(ciphertext)} bytes)")

    # 4. Decryption with receiver's private key
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    print(f"[Decrypted Message] {decrypted.decode()}")
    print(f"[Match Original?] {decrypted == message}")

    # 5. Attack demonstration: no integrity/authentication check
    tampered = bytearray(ciphertext)
    tampered[10] ^= 0xFF  # flip a byte in transit
    try:
        private_key.decrypt(
            bytes(tampered),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        print("[Attack Test] Tampered ciphertext decrypted WITHOUT detection!")
    except Exception as e:
        print(f"[Attack Test] OAEP padding check failed on tamper: {type(e).__name__}")
        print("  -> Note: this only detects gross corruption; RSA-OAEP alone still")
        print("     provides NO sender authentication and NO non-repudiation.")

    return private_key, public_key


# ---------------------------------------------------------------------
# STRATEGY B: RSA + Diffie-Hellman Key Exchange + Hashing
# ---------------------------------------------------------------------
def strategy_b():
    print(SEP + "STRATEGY B - Secure Key Establishment (RSA + DH + Hash)" + SEP)

    # 1. Diffie-Hellman domain parameters (2048-bit safe prime group)
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    print("[DH Parameters] 2048-bit DH group generated (shared publicly).")

    # 2. Each party generates a DH key pair
    branch_private = parameters.generate_private_key()
    branch_public = branch_private.public_key()

    headoffice_private = parameters.generate_private_key()
    headoffice_public = headoffice_private.public_key()

    # 3. Each party computes the shared secret independently
    branch_shared = branch_private.exchange(headoffice_public)
    headoffice_shared = headoffice_private.exchange(branch_public)
    print(f"[DH Exchange] Shared secrets match: {branch_shared == headoffice_shared}")

    # 4. Derive a symmetric session key via HKDF
    session_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"csa51-session-key"
    ).derive(branch_shared)
    print(f"[Session Key] {session_key.hex()[:32]}... (32 bytes, derived via HKDF-SHA256)")

    # 5. Encrypt the transaction using the session key (AES-GCM)
    message = b"TXN: Acc4471 -> Acc9902; Amount=250000.00; Ref=INV20981"
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    print(f"[Encrypted Payload] {ciphertext.hex()[:64]}...")

    # 6. Hash the ORIGINAL message for integrity verification
    digest = hashlib.sha256(message).hexdigest()
    print(f"[SHA-256 Digest sent alongside payload] {digest}")

    # 7. Receiver decrypts and verifies integrity
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    digest_check = hashlib.sha256(decrypted).hexdigest()
    print(f"[Receiver Decrypted] {decrypted.decode()}")
    print(f"[Integrity OK?] {digest_check == digest}")

    # 8. Attack demonstration: message tampering is now detectable
    tampered_message = b"TXN: Acc4471 -> Acc9902; Amount=950000.00; Ref=INV20981"
    tampered_digest = hashlib.sha256(tampered_message).hexdigest()
    print(f"[Attack Test] Tampered message digest:  {tampered_digest}")
    print(f"[Attack Test] Original message digest:  {digest}")
    print(f"[Attack Test] Tamper detected? {tampered_digest != digest}")
    print("  -> Note: a hash alone can be recomputed by ANY party, so this still")
    print("     does not prove WHO sent the message (no authentication yet).")


# ---------------------------------------------------------------------
# STRATEGY C: RSA + DH + Hash + Digital Signature + X.509 Authentication
# ---------------------------------------------------------------------
def strategy_c():
    print(SEP + "STRATEGY C - Trusted Cryptographic Security "
                 "(RSA + DH + Hash + Signature + X.509)" + SEP)

    # 1. Create a self-signed CA (root of trust)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSA51-Bank-RootCA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "CSA51 Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    print(f"[CA Certificate] Issued: CN={ca_cert.subject.rfc4514_string()}")

    # 2. Branch server generates its own key pair and requests a certificate
    branch_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    branch_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSA51-Bank-Branch"),
        x509.NameAttribute(NameOID.COMMON_NAME, "branch01.csa51bank.local"),
    ])
    branch_cert = (
        x509.CertificateBuilder()
        .subject_name(branch_subject).issuer_name(ca_name)
        .public_key(branch_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())   # <-- signed by the CA, not self-signed
    )
    print(f"[Branch Certificate] Issued by CA: CN={branch_cert.subject.rfc4514_string()}")

    # 3. Receiver verifies the certificate chain (CA signature check)
    try:
        ca_key.public_key().verify(
            branch_cert.signature,
            branch_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            branch_cert.signature_hash_algorithm,
        )
        print("[Certificate Verification] PASSED - branch certificate is authentic "
              "and signed by the trusted CA.")
    except Exception:
        print("[Certificate Verification] FAILED")

    # 4. DH key exchange (same as Strategy B) for session key
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    branch_dh_priv = parameters.generate_private_key()
    ho_dh_priv = parameters.generate_private_key()
    shared = branch_dh_priv.exchange(ho_dh_priv.public_key())
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                        info=b"csa51-session-key").derive(shared)

    # 5. Encrypt transaction, hash it, and SIGN the hash with branch's private key
    message = b"TXN: Acc4471 -> Acc9902; Amount=250000.00; Ref=INV20981"
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)

    digest = hashlib.sha256(message).digest()
    signature = branch_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print(f"[Message Signed] Signature (first 32 bytes hex): {signature.hex()[:64]}...")

    # 6. Receiver verifies signature using the CERTIFIED public key
    receiver_public_key = branch_cert.public_key()  # obtained from the verified cert
    try:
        receiver_public_key.verify(
            signature, digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("[Signature Verification] PASSED - message is authentic, unaltered, "
              "and non-repudiable (sender identity confirmed via certificate).")
    except Exception:
        print("[Signature Verification] FAILED")

    # 7. Attack demonstration: impersonation attempt
    print("\n[Attack Test] Impersonation attempt using an UNCERTIFIED key pair:")
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_signature = attacker_key.sign(
        digest,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    try:
        receiver_public_key.verify(  # still checked against the LEGITIMATE branch cert
            forged_signature, digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("  -> Impersonation succeeded (should not happen).")
    except Exception:
        print("  -> Impersonation DETECTED and REJECTED: signature does not match "
              "the certified public key of the claimed sender.")

    # 8. Attack demonstration: tampered message after signing
    print("\n[Attack Test] Message tampered after signing (amount changed):")
    tampered_message = b"TXN: Acc4471 -> Acc9902; Amount=950000.00; Ref=INV20981"
    tampered_digest = hashlib.sha256(tampered_message).digest()
    try:
        receiver_public_key.verify(
            signature, tampered_digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("  -> Tampering NOT detected (should not happen).")
    except Exception:
        print("  -> Tampering DETECTED and REJECTED: signature does not match "
              "the recomputed digest of the modified message.")


if __name__ == "__main__":
    strategy_a()
    strategy_b()
    strategy_c()
    print(SEP + "END OF DEMONSTRATION" + SEP)
