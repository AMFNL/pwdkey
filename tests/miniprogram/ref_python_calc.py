"""Reference implementation of the device-side crypto (Python) for cross-checking
the mini-program's JS implementation. Same formulas as the firmware.
"""
import hashlib
import hmac
import sys

pwd = sys.argv[1].encode("utf-8")
salt = bytes.fromhex(sys.argv[2])
iters = int(sys.argv[3])
nonce = bytes.fromhex(sys.argv[4])
seq = int(sys.argv[5])

kek = hashlib.pbkdf2_hmac("sha256", pwd, salt, iters, 32)
verifier = hmac.new(kek, b"PWD_MGR_VERIFIER_V1", hashlib.sha256).digest()
proof = hmac.new(verifier, nonce + seq.to_bytes(4, "little"), hashlib.sha256).digest()

print(kek.hex())
print(verifier.hex())
print(proof.hex())
