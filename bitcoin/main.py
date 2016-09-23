#!/usr/bin/python
import secp256k1

from .py2specials import *
from .py3specials import *
import binascii
import hashlib
import re
import os
import base64
import time
import random
import hmac
from bitcoin.ripemd import *

# Hashing transactions for signing

SIGHASH_ALL = 0x00000001
SIGHASH_NONE = 0x00000002
SIGHASH_SINGLE = 0x00000003
# this works like SIGHASH_ANYONECANPAY | SIGHASH_ALL, might as well make it explicit while
# we fix the constant
SIGHASH_ANYONECANPAY = 0x00000080


# Elliptic curve parameters (secp256k1)

P = 2**256 - 2**32 - 977
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)


def change_curve(p, n, a, b, gx, gy):
    global P, N, A, B, Gx, Gy, G
    P, N, A, B, Gx, Gy = p, n, a, b, gx, gy
    G = (Gx, Gy)


def getG():
    return G

# Extended Euclidean Algorithm


def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n



# JSON access (for pybtctool convenience)


def access(obj, prop):
    if isinstance(obj, dict):
        if prop in obj:
            return obj[prop]
        elif '.' in prop:
            return obj[float(prop)]
        else:
            return obj[int(prop)]
    else:
        return obj[int(prop)]


def multiaccess(obj, prop):
    return [access(o, prop) for o in obj]


def slice(obj, start=0, end=2**200):
    return obj[int(start):int(end)]


def count(obj):
    return len(obj)

_sum = sum


def sum(obj):
    return _sum(obj)


def isinf(p):
    return p[0] == 0 and p[1] == 0

# Functions for handling pubkey and privkey formats

def get_pubkey_format(pub):
    if is_python2:
        two = '\x02'
        three = '\x03'
        four = '\x04'
    else:
        two = 2
        three = 3
        four = 4

    if isinstance(pub, (tuple, list)): return 'decimal'
    elif len(pub) == 65 and pub[0] == four: return 'bin'
    elif len(pub) == 130 and pub[0:2] == '04': return 'hex'
    elif len(pub) == 33 and pub[0] in [two, three]: return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in ['02', '03']: return 'hex_compressed'
    elif len(pub) == 64: return 'bin_electrum'
    elif len(pub) == 128: return 'hex_electrum'
    else: raise Exception("Pubkey not in recognized format")


def encode_pubkey(pub, formt):
    if not isinstance(pub, (tuple, list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return b'\x04' + encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'bin_compressed':
        return from_int_to_byte(2+(pub[1] % 2)) + encode(pub[0], 256, 32)
    elif formt == 'hex': return '04' + encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    elif formt == 'hex_compressed':
        return '0'+str(2+(pub[1] % 2)) + encode(pub[0], 16, 64)
    elif formt == 'bin_electrum': return encode(pub[0], 256, 32) + encode(pub[1], 256, 32)
    elif formt == 'hex_electrum': return encode(pub[0], 16, 64) + encode(pub[1], 16, 64)
    else: raise Exception("Invalid format!")


def decode_pubkey(pub, formt=None):
    if not formt: formt = get_pubkey_format(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return (decode(pub[1:33], 256), decode(pub[33:65], 256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33], 256)
        beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))
        y = (P-beta) if ((beta + from_byte_to_int(pub[0])) % 2) else beta
        return (x, y)
    elif formt == 'hex': return (decode(pub[2:66], 16), decode(pub[66:130], 16))
    elif formt == 'hex_compressed':
        return decode_pubkey(safe_from_hex(pub), 'bin_compressed')
    elif formt == 'bin_electrum':
        return (decode(pub[:32], 256), decode(pub[32:64], 256))
    elif formt == 'hex_electrum':
        return (decode(pub[:64], 16), decode(pub[64:128], 16))
    else: raise Exception("Invalid format!")

def get_privkey_format(priv):
    if isinstance(priv, int_types): return 'decimal'
    elif len(priv) == 32: return 'bin'
    elif len(priv) == 33: return 'bin_compressed'
    elif len(priv) == 64: return 'hex'
    elif len(priv) == 66: return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return 'wif'
        elif len(bin_p) == 33: return 'wif_compressed'
        else: raise Exception("WIF does not represent privkey")

def encode_privkey(priv, formt, vbyte=0):
    if not isinstance(priv, int_types):
        return encode_privkey(decode_privkey(priv), formt, vbyte)
    if formt == 'decimal': return priv
    elif formt == 'bin': return encode(priv, 256, 32)
    elif formt == 'bin_compressed': return encode(priv, 256, 32)+b'\x01'
    elif formt == 'hex': return encode(priv, 16, 64)
    elif formt == 'hex_compressed': return encode(priv, 16, 64)+'01'
    elif formt == 'wif':
        return bin_to_b58check(encode(priv, 256, 32), 128+int(vbyte))
    elif formt == 'wif_compressed':
        return bin_to_b58check(encode(priv, 256, 32)+b'\x01', 128+int(vbyte))
    else: raise Exception("Invalid format!")

def decode_privkey(priv,formt=None):
    if not formt: formt = get_privkey_format(priv)
    if formt == 'decimal': return priv
    elif formt == 'bin': return decode(priv, 256)
    elif formt == 'bin_compressed': return decode(priv[:32], 256)
    elif formt == 'hex': return decode(priv, 16)
    elif formt == 'hex_compressed': return decode(priv[:64], 16)
    elif formt == 'wif': return decode(b58check_to_bin(priv),256)
    elif formt == 'wif_compressed':
        return decode(b58check_to_bin(priv)[:32],256)
    else: raise Exception("WIF does not represent privkey")

def add_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    return encode_privkey((decode_privkey(p1, f1) + decode_privkey(p2, f2)) % N, f1)

def mul_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    return encode_privkey((decode_privkey(p1, f1) * decode_privkey(p2, f2)) % N, f1)


def divide(pubkey, privkey):
    factor = inv(decode_privkey(privkey), N)
    return multiply(pubkey, factor)


def compress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' in f: return pubkey
    elif f == 'bin': return encode_pubkey(decode_pubkey(pubkey, f), 'bin_compressed')
    elif f == 'hex' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey, f), 'hex_compressed')


def decompress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' not in f: return pubkey
    elif f == 'bin_compressed': return encode_pubkey(decode_pubkey(pubkey, f), 'bin')
    elif f == 'hex_compressed' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey, f), 'hex')



def privkey_to_address(priv, magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv), magicbyte)
privtoaddr = privkey_to_address


def neg_pubkey(pubkey):
    f = get_pubkey_format(pubkey)
    pubkey = decode_pubkey(pubkey, f)
    return encode_pubkey((pubkey[0], (P-pubkey[1]) % P), f)


def neg_privkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey, f)
    return encode_privkey((N - privkey) % N, f)


def subtract_privkeys(p1, p2):
    f1, f2 = get_privkey_format(p1), get_privkey_format(p2)
    k2 = decode_privkey(p2, f2)
    return encode_privkey((decode_privkey(p1, f1) - k2) % N, f1)

# Hashes


def bin_hash160(string):
    intermed = hashlib.sha256(string).digest()
    try:
        digest = hashlib.new('ripemd160', intermed).digest()
    except:
        digest = RIPEMD160(intermed).digest()
    return digest


def hash160(string):
    return safe_hexlify(bin_hash160(string))


def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string, 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bytes_to_hex_string(bin_sha256(string))


def bin_ripemd160(string):
    try:
        digest = hashlib.new('ripemd160', string).digest()
    except:
        digest = RIPEMD160(string).digest()
    return digest


def ripemd160(string):
    return safe_hexlify(bin_ripemd160(string))


def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()


def dbl_sha256(string):
    return safe_hexlify(bin_dbl_sha256(string))


def bin_slowsha(string):
    string = from_string_to_bytes(string)
    orig_input = string
    for _ in range(100000):
        string = hashlib.sha256(string + orig_input).digest()
    return string


def slowsha(string):
    return safe_hexlify(bin_slowsha(string))


def hash_to_int(x):
    if len(x) in [40, 64]:
        return decode(x, 16)
    return decode(x, 256)


def num_to_var_int(x):
    x = int(x)
    if x < 253: return from_int_to_byte(x)
    elif x < 65536: return from_int_to_byte(253)+encode(x, 256, 2)[::-1]
    elif x < 4294967296: return from_int_to_byte(254) + encode(x, 256, 4)[::-1]
    else: return from_int_to_byte(255) + encode(x, 256, 8)[::-1]


# WTF, Electrum?
def electrum_sig_hash(message):
    padded = b"\x18Bitcoin Signed Message:\n" + num_to_var_int(len(message)) + from_string_to_bytes(message)
    return bin_dbl_sha256(padded)


def random_key():
    # Gotta be secure after that java.SecureRandom fiasco...
    entropy = random_string(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)


def random_electrum_seed():
    entropy = os.urandom(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)[:32]

# Encodings

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]


def get_version_byte(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return ord(data[0])


def hex_to_b58check(inp, magicbyte=0):
    return bin_to_b58check(binascii.unhexlify(inp), magicbyte)


def b58check_to_hex(inp):
    return safe_hexlify(b58check_to_bin(inp))


def pubkey_to_address(pubkey, magicbyte=0):
    if isinstance(pubkey, (list, tuple)):
        pubkey = encode_pubkey(pubkey, 'bin')
    if len(pubkey) in [66, 130]:
        return bin_to_b58check(
            bin_hash160(binascii.unhexlify(pubkey)), magicbyte)
    return bin_to_b58check(bin_hash160(pubkey), magicbyte)

pubtoaddr = pubkey_to_address


def is_privkey(priv):
    try:
        get_privkey_format(priv)
        return True
    except:
        return False

def is_pubkey(pubkey):
    try:
        get_pubkey_format(pubkey)
        return True
    except:
        return False

def is_address(addr):
    ADDR_RE = re.compile("^[123mn][a-km-zA-HJ-NP-Z0-9]{26,33}$")
    return bool(ADDR_RE.match(addr))


# EDCSA


def encode_sig(v, r, s):
    vb, rb, sb = from_int_to_byte(v), encode(r, 256), encode(s, 256)
    
    result = base64.b64encode(vb+b'\x00'*(32-len(rb))+rb+b'\x00'*(32-len(sb))+sb)
    return result if is_python2 else str(result, 'utf-8')


def decode_sig(sig):
    bytez = base64.b64decode(sig)
    return from_byte_to_int(bytez[0]), decode(bytez[1:33], 256), decode(bytez[33:], 256)

# https://tools.ietf.org/html/rfc6979#section-3.2


def deterministic_generate_k(msghash, priv):
    v = b'\x01' * 32
    k = b'\x00' * 32
    priv = encode_privkey(priv, 'bin')
    msghash = encode(hash_to_int(msghash), 256, 32)
    k = hmac.new(k, v+b'\x00'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v+b'\x01'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    return decode(hmac.new(k, v, hashlib.sha256).digest(), 256)


def ecdsa_sign(msg, priv):
    v, r, s = ecdsa_raw_sign(electrum_sig_hash(msg), priv)
    sig = encode_sig(v, r, s)
    assert ecdsa_verify(msg, sig, 
        privtopub(priv)), "Bad Sig!\t %s\nv = %d\n,r = %d\ns = %d" % (sig, v, r, s)
    return sig


# For BitcoinCore, (msg = addr or msg = "") be default
def ecdsa_verify_addr(msg, sig, addr):
    assert is_address(addr)
    Q = ecdsa_recover(msg, sig)
    magic = get_version_byte(addr)
    return (addr == pubtoaddr(Q, int(magic))) or (addr == pubtoaddr(compress(Q), int(magic)))


def ecdsa_verify(msg, sig, pub):
    if is_address(pub):
        return ecdsa_verify_addr(msg, sig, pub)
    return ecdsa_raw_verify(electrum_sig_hash(msg), decode_sig(sig), pub)


def ecdsa_recover(msg, sig):
    v,r,s = decode_sig(sig)
    Q = ecdsa_raw_recover(electrum_sig_hash(msg), (v,r,s))
    return encode_pubkey(Q, 'hex_compressed') if v >= 31 else encode_pubkey(Q, 'hex')


def der_encode_sig(v, r, s):
    b1, b2 = safe_hexlify(encode(r, 256)), safe_hexlify(encode(s, 256))
    if len(b1) and b1[0] in '89abcdef':
        b1 = '00' + b1
    if len(b2) and b2[0] in '89abcdef':
        b2 = '00' + b2
    left = '02'+encode(len(b1)//2, 16, 2)+b1
    right = '02'+encode(len(b2)//2, 16, 2)+b2
    return '30'+encode(len(left+right)//2, 16, 2)+left+right


def der_decode_sig(sig):
    leftlenbytes = decode(sig[6:8], 16)
    leftlen = leftlenbytes*2
    left = sig[8:8+leftlen]
    rightlenbytes = decode(sig[10+leftlen:12+leftlen], 16)
    rightlen = rightlenbytes*2
    right = sig[12+leftlen:12+leftlen+rightlen]
    return (leftlenbytes, decode(left, 16), rightlenbytes, decode(right, 16))


def _normalize_vrs(vrs):
    v, r, s = vrs
    v = v - 27 if v > 3 else v
    if not (0 <= v < 3):
        raise ValueError('invalid rec_id: {}'.format(v))
    return v, r, s


def ecdsa_raw_sign(msghash, priv):
    key = secp256k1.PrivateKey(encode_privkey(priv, 'bin'))
    msghash = safe_from_hex(msghash) if is_hex(msghash) else msghash
    sig_check = key.ecdsa_sign_recoverable(msghash, raw=True)
    secp256k1_sig = key.ecdsa_recoverable_serialize(sig_check)
    v = secp256k1_sig[1] + 27
    if 'compressed' in get_privkey_format(priv):
        v += 4
    r, s = hash_to_int(secp256k1_sig[0][:32]), hash_to_int(secp256k1_sig[0][32:])
    return long(v), r, s


def ecdsa_raw_verify(msghash, vrs, pub):
    vr, r, vs, s = vrs
    if not (27 <= vr <= 34):
        return False
    if not (27 <= vs <= 34):
        return False
    key = secp256k1.PublicKey(pubkey=encode_pubkey(pub, 'bin'), raw=True)
    sig_bytes = safe_from_hex(der_encode_sig(None, r, s))
    try:
        raw_sig = key.ecdsa_deserialize(sig_bytes)
    except AssertionError as e:
        raise e
    msghash = safe_from_hex(msghash) if is_hex(msghash) else msghash
    return key.ecdsa_verify(msghash, raw_sig, raw=True)


def ecdsa_raw_recover(msghash, vrs):
    v, r, s = _normalize_vrs(vrs)
    p = secp256k1.PublicKey(flags=secp256k1.ALL_FLAGS)
    msghash = safe_from_hex(msghash) if is_hex(msghash) else msghash
    sig = encode(r, 256) + encode(s, 256)
    recoverable = p.ecdsa_recoverable_deserialize(sig, rec_id=v)
    pubkey = p.ecdsa_recover(msghash, recoverable, raw=True)
    ser_pubkey = secp256k1.PublicKey(pubkey).serialize()
    return decode_pubkey(ser_pubkey)


def privkey_to_pubkey(privkey):
    key = secp256k1.PrivateKey(encode_privkey(privkey, 'bin'))
    pubkey = key.pubkey.serialize()
    return encode_pubkey(pubkey, get_privkey_format(privkey))
privtopub = privkey_to_pubkey


def add_pubkeys(p1, p2):
    fmt = get_pubkey_format(p1) # the first key rules
    keys = [secp256k1.PublicKey(encode_pubkey(p1, 'bin'), raw=True).public_key,
            secp256k1.PublicKey(encode_pubkey(p2, 'bin'), raw=True).public_key]
    new = secp256k1.PublicKey()
    new.combine(keys)
    return encode_pubkey(new.serialize(), fmt)


def multiply(pubkey, privkey):
    fmt = get_pubkey_format(pubkey)
    pub = secp256k1.PublicKey(encode_pubkey(pubkey, 'bin'), raw=True)
    priv = secp256k1.PrivateKey(encode_privkey(privkey, 'bin'), raw=True)
    mul = pub.tweak_mul(safe_from_hex(priv.serialize())).serialize()
    return encode_pubkey(mul, fmt)


def subtract_pubkeys(p1, p2):
    if p1 == p2:
        return b'\x02' + b'\x00' *32
    fmt = get_pubkey_format(p1)
    d = decode_pubkey(p2, get_pubkey_format(p2))
    p2 = (d[0], (P - d[1]) % P)
    k1 = secp256k1.PublicKey(encode_pubkey(p1, 'bin'), raw=True).public_key
    k2 = secp256k1.PublicKey(encode_pubkey(p2, 'bin'), raw=True).public_key
    new = secp256k1.PublicKey()
    new.combine([k1, k2])
    return encode_pubkey(new.serialize(), fmt)
