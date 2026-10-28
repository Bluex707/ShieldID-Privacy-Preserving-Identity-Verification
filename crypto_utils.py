
import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from ecdsa import SECP256k1, ellipticcurve



def generate_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def public_key_from_pem(pem_str):
    return serialization.load_pem_public_key(pem_str.encode())


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def sign_payload(private_key, payload: dict) -> str:
    signature = private_key.sign(canonical_json_bytes(payload), _PSS, hashes.SHA256())
    return base64.b64encode(signature).decode()


def verify_signature(public_key, payload: dict, signature_b64) -> bool:
    """True only for a valid signature. Never raises on malformed input."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, canonical_json_bytes(payload), _PSS, hashes.SHA256())
        return True
    except Exception:  
        return False



_CURVE = SECP256k1
_G = _CURVE.generator
_N = _CURVE.order
_P = _CURVE.curve.p()
_HEX = frozenset("0123456789abcdefABCDEF")


def generate_ec_keypair():
    
    private_int = secrets.randbelow(_N - 1) + 1
    return private_int, private_int * _G


def ec_point_to_hex(point) -> str:
    return f"{point.x():064x}{point.y():064x}"


def ec_point_from_hex(hex_str):
    
    if not isinstance(hex_str, str) or len(hex_str) != 128 or not _HEX.issuperset(hex_str):
        raise ValueError("EC point must be 128 hex characters")
    x = int(hex_str[:64], 16)
    y = int(hex_str[64:], 16)
    if not (0 <= x < _P and 0 <= y < _P) or not _CURVE.curve.contains_point(x, y):
        raise ValueError("point is not on secp256k1")
    return ellipticcurve.Point(_CURVE.curve, x, y)


def _parse_proof(proof):
   
    if not isinstance(proof, dict):
        raise ValueError("proof must be an object")
    R = ec_point_from_hex(proof.get("R"))
    s_raw = proof.get("s")
    if not isinstance(s_raw, str) or not s_raw.isdigit() or len(s_raw) > 80:
        raise ValueError("bad scalar")
    s = int(s_raw)
    if not 0 < s < _N:
        raise ValueError("scalar out of range")
    return R, s


def _schnorr_challenge(R_point, public_point, context: bytes) -> int:
    h = hashlib.sha256()
    h.update(ec_point_to_hex(R_point).encode())
    h.update(ec_point_to_hex(public_point).encode())
    h.update(context)
    return int.from_bytes(h.digest(), "big") % _N


def schnorr_prove(private_int: int, public_point, context: bytes) -> dict:
    
    k = secrets.randbelow(_N - 1) + 1
    R = k * _G
    c = _schnorr_challenge(R, public_point, context)
    s = (k + c * private_int) % _N
    return {"R": ec_point_to_hex(R), "s": str(s)}


def schnorr_verify(public_point, proof: dict, context: bytes) -> bool:
   
    try:
        R, s = _parse_proof(proof)
        c = _schnorr_challenge(R, public_point, context)
        return (s * _G) == (R + c * public_point)
    except (ValueError, TypeError, KeyError, AssertionError, ArithmeticError):
        return False





def _generate_nums_point(label: bytes):
    
    x = int.from_bytes(hashlib.sha256(label).digest(), "big") % _P
    while True:
        rhs = (pow(x, 3, _P) + 7) % _P          # secp256k1: y^2 = x^3 + 7
        y = pow(rhs, (_P + 1) // 4, _P)         # valid sqrt since p % 4 == 3
        if (y * y) % _P == rhs:
            return ellipticcurve.Point(_CURVE.curve, x, y)
        x = (x + 1) % _P


_H = _generate_nums_point(b"shieldid-pedersen-H-generator-v1")


def encode_attribute_value(value) -> int:
    
    digest = hashlib.sha256(f"attr:{value}".encode()).digest()
    return int.from_bytes(digest, "big") % _N


def pedersen_commit(value, blinding: int = None):
    
    m = encode_attribute_value(value)
    r = blinding if blinding is not None else secrets.randbelow(_N - 1) + 1
    return r, (m * _G) + (r * _H)


def pedersen_open_verify(commitment_point, value, blinding) -> bool:
    
    try:
        if isinstance(blinding, bool) or not isinstance(blinding, int) or not 0 < blinding < _N:
            return False
        m = encode_attribute_value(value)
        return commitment_point == (m * _G) + (blinding * _H)
    except (ValueError, TypeError, AssertionError, ArithmeticError):
        return False


def _attr_equality_challenge(R_point, D_point, context: bytes) -> int:
    h = hashlib.sha256()
    h.update(b"attr-eq")
    h.update(ec_point_to_hex(R_point).encode())
    h.update(ec_point_to_hex(D_point).encode())
    h.update(context)
    return int.from_bytes(h.digest(), "big") % _N


def prove_attribute_equals(blinding_r: int, commitment_point, known_value, context: bytes) -> dict:
    
    m = encode_attribute_value(known_value)
    D = commitment_point + (((_N - m) % _N) * _G)
    k = secrets.randbelow(_N - 1) + 1
    R = k * _H
    c = _attr_equality_challenge(R, D, context)
    s = (k + c * blinding_r) % _N
    return {"R": ec_point_to_hex(R), "s": str(s)}


def verify_attribute_equals(commitment_point, known_value, proof: dict, context: bytes) -> bool:
    try:
        R, s = _parse_proof(proof)
        m = encode_attribute_value(known_value)
        D = commitment_point + (((_N - m) % _N) * _G)
        c = _attr_equality_challenge(R, D, context)
        return (s * _H) == (R + c * D)
    except (ValueError, TypeError, KeyError, AssertionError, ArithmeticError):
        return False
