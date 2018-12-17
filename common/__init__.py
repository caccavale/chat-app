import base64
import json as _json


def _b64_to_bytes(encoded: str) -> bytes:
    return base64.b64decode(encoded.encode('ascii'))

def _bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

assert(_b64_to_bytes(_bytes_to_b64(b'wololol')) == b'wololol')

class _ByteEncoder(_json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return _bytes_to_b64(o)
        return _json.JSONEncoder.default(self, o)

def dumpb(o):
    return _json.dumps(o, cls=_ByteEncoder).encode()


class _ByteDecoder(_json.JSONDecoder):
    def __init__(self):
        super().__init__(object_pairs_hook=self.b64)

    def b64(self, o):
        return {k: _b64_to_bytes(v) if isinstance(v, str)
                else v for k, v in o}

def loadb(j):
    return _json.loads(j.decode(), cls=_ByteDecoder)