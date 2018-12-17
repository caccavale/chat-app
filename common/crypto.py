import os
import time

from typing import Tuple, Callable
from common import loadb, dumpb

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

backend = default_backend()

from dataclasses import dataclass

@dataclass
class Notary:
    raw_public_key: bytes = b''
    raw_private_key: bytes = b''
    public_key: None = None
    private_key: None = None
    password: str = b'a very weak password'

    hash: Callable = hashes.SHA256
    random: Callable = os.urandom
    timestamp: Callable = time.time

    def load_keys(self):
        self.public_key = serialization.load_pem_public_key(self.raw_public_key, backend=backend)
        self.private_key = serialization.load_pem_private_key(self.raw_private_key, self.password, backend=backend)

    def issue_challenge(self):
        challenge = {
            'nonce': self.random(32),
            'time': self.timestamp(),
            'difficulty': 2,
        }

        return {
            'challenge': challenge,
            'signature': self.sign(dumpb(challenge))
        }

    def solve_challenge(self, message):
        n = -1
        attempt = b'not it'
        challenge = message['challenge']

        while not attempt.startswith(challenge['difficulty'] * b'\x00'):
            n = n + 1

            digest = hashes.Hash(self.hash(), backend=backend)
            digest.update(challenge['nonce'] + n.to_bytes(32, byteorder='big'))
            attempt = digest.finalize()

        message['response'] = n

        return message

    def verify_challenge(self, message):
        try:
            hashee = message['challenge']['nonce'] + message['response'].to_bytes(32, byteorder='big')
            digest = hashes.Hash(self.hash(), backend=backend)
            digest.update(hashee)
            proof = digest.finalize()

            if not proof.startswith(message['challenge']['difficulty'] * b'\x00'):
                return False # Insufficient answer

            if not len(hashee) == 64:
                return False # Insufficient length

            if self.timestamp() - message['challenge']['time'] > 10:
                return False # Expired challenge

            return self.verify(dumpb(message['challenge']), message['signature'], self.raw_public_key)
        except ValueError:
            return False

    def issue_proof(self):
        proof = {
            'nonce': self.random(32),
            'time': self.timestamp(),
        }

        return {
            'proof': proof,
            'notary_signature': self.sign(dumpb(proof))
        }

    def solve_proof(self, message):
        message['signature'] = self.sign(dumpb(message['proof']))
        return message

    def verify_proof(self, message, raw_public_key):
        try:
            if not self.verify(dumpb(message['proof']), message['signature'], raw_public_key):
                return False
            if not self.verify(dumpb(message['proof']), message['notary_signature'], self.raw_public_key):
                return False

            if self.timestamp() - message['proof']['time'] > 10:
                return False # Expired challenge

            return True
        except ValueError:
            return False

    def sign(self, text):
        return self.private_key.sign(
            text,
            padding.PSS(
                mgf=padding.MGF1(self.hash()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self.hash()
        )

    def verify(self, text, signature, raw_public_key):
        public_key = serialization.load_pem_public_key(raw_public_key, backend=backend)
        try:
            public_key.verify(
                signature,
                text,
                padding.PSS(
                    mgf=padding.MGF1(self.hash()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self.hash()
            )
            return True
        except:
            return False

    def encrypt(self, plaintext, raw_public_key):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        public_key = serialization.load_pem_public_key(raw_public_key, backend=backend)

        key = self.random(32)
        iv = self.random(16)
        encryptor = Cipher(algorithms.AES(key),
                           modes.GCM(iv),
                           backend=backend).encryptor()

        cipher_text = b''
        block_size = algorithms.AES.block_size

        # Prepend with the length of plaintext + the int in bytes
        plaintext = (len(plaintext) + 4).to_bytes(4, 'big') + plaintext
        # Left pad with spaces to a multiple of AES block_size
        plaintext = plaintext.ljust(
            len(plaintext) + block_size - (len(plaintext) % block_size))

        # Feed in each block
        for i, block in enumerate([plaintext[lb: lb + block_size] for lb in
                                   range(0, len(plaintext), block_size)]):
            cipher_text += encryptor.update(block)
        cipher_text += encryptor.finalize()

        # Encrypt the AES key and IV with the receivers public key
        secrets = public_key.encrypt(dumpb({'key': key,
                                            'iv': iv}),
                                     padding.OAEP(
                                        mgf=padding.MGF1(
                                            algorithm=self.hash()
                                        ),
                                     algorithm=self.hash(),
                                     label=None
                                     )
        )

        return {
            'secrets': secrets,
            'tag': encryptor.tag,
            'cipher_text': cipher_text,
        }

    def decrypt(self, bundle):
        # Decrypt the AES key and IV with the receivers private key
        bundle.update(
            loadb(
                self.private_key.decrypt(
                    bundle['secrets'],
                    padding.OAEP(
                        mgf = padding.MGF1(algorithm=self.hash()),
                        algorithm = self.hash(),
                        label = None
                    )
                )
            )
        )

        # Decrypt payload with AES key and IV
        decryptor = Cipher(
            algorithms.AES(bundle['key']),
            modes.GCM(bundle['iv'], bundle['tag']),
            backend=backend).decryptor()

        plaintext = b''
        block_size = algorithms.AES.block_size

        for block in [bundle['cipher_text'][lb: lb + block_size] for lb in
                      range(0, len(bundle['cipher_text']), block_size)]:
            plaintext += decryptor.update(block)
        plaintext += decryptor.finalize()

        # Return without padding
        return plaintext[4 : int.from_bytes(plaintext[:4], 'big')]

    def derive_key(self, password):
        hkdf = HKDF(
            algorithm = self.hash(),
            length = 32,
            salt = None,
            info = None,
            backend = backend
        )
        return hkdf.derive(password)

    def recover_key(self, user_info, password_derived_key):
        decryptor = Cipher(
            algorithms.AES(password_derived_key),
            modes.GCM(user_info['iv'], user_info['tag']),
            backend=backend).decryptor()

        raw_private_key = b''
        block_size = algorithms.AES.block_size

        for block in [user_info['private_key'][lb: lb + block_size] for lb in
                      range(0, len(user_info['private_key']), block_size)]:
            raw_private_key += decryptor.update(block)
        raw_private_key += decryptor.finalize()

        return raw_private_key[4 : int.from_bytes(raw_private_key[:4], 'big')]

    @classmethod
    def keygen(cls):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=backend
        )
        public_key = private_key.public_key()

        raw_private_key = private_key.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.PKCS8,
                                                    serialization.BestAvailableEncryption(
                                                        cls.password
                                                    )
                                                    )
        raw_public_key = public_key.public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)

        return raw_private_key, raw_public_key

    def hide_key(self, private_key, password_derived_key):
        iv = self.random(16)
        encryptor = Cipher(algorithms.AES(password_derived_key),
                           modes.GCM(iv),
                           backend=backend).encryptor()

        cipher_text = b''
        block_size = algorithms.AES.block_size

        # Prepend with the length of plaintext + the int in bytes
        plaintext = (len(private_key) + 4).to_bytes(4, 'big') + private_key
        # Left pad with spaces to a multiple of AES block_size
        plaintext = plaintext.ljust(
            len(plaintext) + block_size - (len(plaintext) % block_size))

        # Feed in each block
        for i, block in enumerate([plaintext[lb: lb + block_size] for lb in
                                   range(0, len(plaintext), block_size)]):
            cipher_text += encryptor.update(block)
        cipher_text += encryptor.finalize()

        # Encrypt the AES key and IV with the receivers public key

        return {
            'iv': iv,
            'private_key': cipher_text,
            'tag': encryptor.tag,
        }


# TODO REMOVE BELOW HERE TODO



'''
/ SHA256 Signature | ------ Payload ------ \ Payload is verified via senders public key
/                    AES, IV | Cipher text \ AES, IV are decrypted with receivers private key
/                              Len | Plain \ Decrypt cypher with the decrypted AES key and IV
'''

class RSAES:
    # I do not attempt to have a password for the private keys as that is
    # not within the requirements for the assignment and the spec of how
    # args are parsed do not allow it.  If it were, this would be taken as
    # user input when loading a key:
    password = b'a very weak password'

    key_encoding = serialization.Encoding.PEM
    private_key_format = serialization.PrivateFormat.PKCS8
    public_key_format = serialization.PublicFormat.SubjectPublicKeyInfo

    hash = hashes.SHA256
    random = os.urandom

    @classmethod
    def _load_keys(cls, public: bytes, private: bytes) -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
        public_key = serialization.load_pem_public_key(public, backend=backend)
        private_key = serialization.load_pem_private_key(private, cls.password, backend=backend)
        assert (isinstance(public_key, rsa.RSAPublicKey))
        assert (isinstance(private_key, rsa.RSAPrivateKey))
        return public_key, private_key

    @classmethod
    def encrypt(cls, plaintext: bytes, dst_public_key: bytes, src_private_key: bytes) -> bytes:

        public_key, private_key = cls._load_keys(dst_public_key, src_private_key)

        # Encrypt plaintext with AES
        key = cls.random(32)
        iv = cls.random(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()

        cipher_text = b''
        block_size = algorithms.AES.block_size

        # Prepend with the length of plaintext + the int in bytes
        plaintext = (len(plaintext) + 4).to_bytes(4, 'big') + plaintext
        # Left pad with spaces to a multiple of AES block_size
        plaintext = plaintext.ljust(len(plaintext) + block_size - (len(plaintext) % block_size))

        print(len(plaintext) / block_size)

        # Feed in each block
        for i, block in enumerate([plaintext[lb : lb + block_size] for lb in range(0, len(plaintext), block_size)]):
            cipher_text += encryptor.update(block)
        cipher_text += encryptor.finalize()

        # Encrypt the AES key and IV with the receivers public key
        secrets = public_key.encrypt(key + iv,
                                     padding.OAEP(
                                         mgf=padding.MGF1(
                                             algorithm=cls.hash()
                                         ),
                                         algorithm=cls.hash(),
                                         label=None
                                     )
        )

        # Sign the whole payload with senders private key
        signature = private_key.sign(
            secrets + cipher_text,
            padding.PSS(
                mgf=padding.MGF1(cls.hash()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            cls.hash()
        )

        return signature + secrets + cipher_text

    @classmethod
    def decrypt(cls, payload, dst_private_key, src_public_key):
        public_key, private_key = cls._load_keys(src_public_key, dst_private_key)

        signature   = payload[  0 : 256]
        secrets     = payload[256 : 512]
        cipher_text = payload[512 : ]

        # Verify the payload with senders public key
        public_key.verify(signature,
                          secrets + cipher_text,
                          padding.PSS(
                              mgf=padding.MGF1(cls.hash()),
                              salt_length=padding.PSS.MAX_LENGTH
                          ),
                          cls.hash()
        )

        # Decrypt the AES key and IV with the receivers private key
        partial = private_key.decrypt(secrets,
                                      padding.OAEP(
                                         mgf = padding.MGF1(algorithm=cls.hash()),
                                         algorithm = cls.hash(),
                                         label = None
                                      )
        )

        AES_key = partial[:32]
        AES_IV  = partial[32:]

        # Decrypt payload with AES key and IV
        cipher = Cipher(algorithms.AES(AES_key), modes.CBC(AES_IV), backend=backend)
        decryptor = cipher.decryptor()

        plaintext = b''
        block_size = algorithms.AES.block_size

        for block in [cipher_text[lb: lb + block_size] for lb in
                      range(0, len(cipher_text), block_size)]:
            plaintext += decryptor.update(block)
        plaintext += decryptor.finalize()

        # Return without padding
        return plaintext[4 : int.from_bytes(plaintext[:4], 'big')]




