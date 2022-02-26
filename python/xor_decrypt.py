import base64
from io import BytesIO
import hmac

from embit import bech32
from embit import compact

def xor_decrypt(key, payload):
    blob = base64.urlsafe_b64decode(payload)
    s = BytesIO(blob)
    variant = s.read(1)[0]
    if variant != 1:
        raise RuntimeError("Not implemented")
    # reading nonce
    l = s.read(1)[0]
    nonce = s.read(l)
    if len(nonce) != l:
        raise RuntimeError("Missing nonce bytes")
    if l < 8:
        raise RuntimeError("Nonce is too short")
    # reading payload
    l = s.read(1)[0]
    payload = s.read(l)
    if len(payload) > 32:
        raise RuntimeError("Payload is too long for this encryption method")
    if len(payload) != l:
        raise RuntimeError("Missing payload bytes")
    hmacval = s.read()
    expected = hmac.new(
        key, b"Data:" + blob[: -len(hmacval)], digestmod="sha256"
    ).digest()
    if len(hmacval) < 8:
        raise RuntimeError("HMAC is too short")
    if hmacval != expected[: len(hmacval)]:
        raise RuntimeError("HMAC is invalid")
    secret = hmac.new(key, b"Round secret:" + nonce, digestmod="sha256").digest()
    payload = bytearray(payload)
    for i in range(len(payload)):
        payload[i] = payload[i] ^ secret[i]
        print("payload[i]" + str(payload[i]));
    s = BytesIO(payload)
    pin = compact.read_from(s)
    amount_in_cent = compact.read_from(s)
    return pin, amount_in_cent

decryptionKey = b"shared-secret-key"
samplePayload = "AQhnxmlzUf9K7AWVl1HO17mbLmpwKbgl"
result = xor_decrypt(decryptionKey, samplePayload)
pin = result[0]
amount_in_cent = result[1]

print("pin=" + str(pin))
print("amount_in_cent=" + str(amount_in_cent))
