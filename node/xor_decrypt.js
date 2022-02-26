const assert = require('assert');
const crypto = require('crypto');

const xor_decrypt = function(key, payload) {
    assert.ok(Buffer.isBuffer(key), new Error('Invalid argument ("key"): Buffer expected'));
    assert.ok(Buffer.isBuffer(payload), new Error('Invalid argument ("payload"): Buffer expected'));
    let pos = 0;
    const variant = payload[pos++];
    if (variant !== 1) {
        throw new Error('Not implemented');
    }
    const nonceLength = payload[pos++];
    const nonce = payload.subarray(pos++, pos += (nonceLength - 1));
    if (nonce.length != nonceLength) {
        throw new Error('Missing nonce bytes');
    }
    if (nonce.length < 8) {
        throw new Error('Nonce is too short');
    }
    const dataLength = payload[pos++];
    const data = payload.subarray(pos++, pos += (dataLength - 1));
    if (data.length > 32) {
        throw new Error('NPayload is too long for this encryption method');
    }
    if (data.length != dataLength) {
        throw new Error('Missing payload bytes');
    }
    const hmac = payload.subarray(pos);
    if (hmac.length < 8) {
        throw new Error('HMAC is too short');
    }
    const expected = crypto.createHmac('sha256', key).update(
        Buffer.concat([
            Buffer.from('Data:', 'utf8'),
            payload.subarray(0, payload.length - hmac.length)
        ])
    ).digest();
    if (hmac.compare(expected.subarray(0, hmac.length))) {
        throw new Error('HMAC is invalid');
    }
    const secret = crypto.createHmac('sha256', key).update(
        Buffer.concat([
            Buffer.from('Round secret:', 'utf8'),
            nonce
        ])
    ).digest();
    let buffer = Buffer.alloc(data.length);
    for (let index = 0; index < data.length; index++) {
        buffer[index] = data[index] ^ secret[index];
    }
    let offset = 0;
    // https://github.com/diybitcoinhardware/embit/blob/a43ee04d8619cdb4bbb84dab60002fd9c987ee60/src/embit/compact.py#L29-L36
    const readFrom = function(buffer) {
        int = buffer[offset++];
        if (int >= 0xFD) {
            const bytesToRead = 2 ** (int - 0xFC);
            int = buffer.readUIntLE(1, bytesToRead);
            offset += bytesToRead;
        }
        return int;
    };
    const pin = readFrom(buffer);
    const amount = readFrom(buffer);
    return { pin, amount };
};

const decryptionKey = Buffer.from('shared-secret-key', 'utf8');
const samplePayload = Buffer.from('AQhnxmlzUf9K7AWVl1HO17mbLmpwKbgl', 'base64');
const { pin, amount } = xor_decrypt(decryptionKey, samplePayload);
// `amount` is an integer number of cents.
console.log({ pin, amount });
