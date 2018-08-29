from ssl import create_default_context, SSLContext
import base58
import hmac
import hashlib
import yaml
import os
import json
import datetime
import keyring
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.x509.name import NameOID, NameAttribute
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging
from twisted.internet import ssl

log = logging.getLogger(__name__)

API_KEY_NAME = "api"
LBRY_SECRET = "LBRY_SECRET"


def sha(x: bytes) -> bytes:
    h = hashlib.sha256(x).digest()
    return base58.b58encode(h)


def generate_key(x: bytes = None) -> bytes:
    if x is None:
        return sha(os.urandom(256))
    else:
        return sha(x)


class APIKey:
    def __init__(self, secret, name, expiration=None):
        self.secret = secret
        self.name = name
        self.expiration = expiration

    @classmethod
    def new(cls, seed=None, name=None, expiration=None):
        secret = generate_key(seed)
        key_name = name if name else sha(secret)
        return APIKey(secret, key_name, expiration)

    def _raw_key(self):
        return base58.b58decode(self.secret)

    def get_hmac(self, message):
        decoded_key = self._raw_key()
        signature = hmac.new(decoded_key, message.encode(), hashlib.sha256)
        return base58.b58encode(signature.digest())

    def compare_hmac(self, message, token):
        decoded_token = base58.b58decode(token)
        target = base58.b58decode(self.get_hmac(message))

        try:
            if len(decoded_token) != len(target):
                return False
            return hmac.compare_digest(decoded_token, target)
        except:
            return False


def load_api_keys(path):
    if not os.path.isfile(path):
        raise Exception("Invalid api key path")

    with open(path, "r") as f:
        data = yaml.load(f.read())

    keys_for_return = {}
    for key_name in data:
        key = data[key_name]
        secret = key['secret'].decode()
        expiration = key['expiration']
        keys_for_return.update({key_name: APIKey(secret, key_name, expiration)})
    return keys_for_return


def save_api_keys(keys, path):
    with open(path, "w") as f:
        key_dict = {keys[key_name].name: {'secret': keys[key_name].secret,
                                          'expiration': keys[key_name].expiration}
                    for key_name in keys}
        data = yaml.safe_dump(key_dict)
        f.write(data)


def initialize_api_key_file(key_path):
    keys = {}
    new_api_key = APIKey.new(name=API_KEY_NAME)
    keys.update({new_api_key.name: new_api_key})
    save_api_keys(keys, key_path)


def get_auth_message(message_dict):
    return json.dumps(message_dict, sort_keys=True)


class Keyring:
    def __init__(self, keyring_obj=None, service_name: str = "lbrynet", dns: str = "localhost",
                 country: str = "US", organization: str = "LBRY", common_name: str = "LBRY API",
                 expiration: int = 365):
        if not keyring_obj:
            keyring_obj = keyring.get_keyring()
        self.keyring = keyring_obj
        self.dns = dns
        self.service_name = service_name
        self.country = country
        self.organization = organization
        self.common_name = common_name
        self.expiration = expiration

    @staticmethod
    def _generate_private_key() -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

    @staticmethod
    def _generate_ssl_certificate(private_key: rsa.RSAPrivateKey, dns: str, country: str, organization: str,
                                 common_name: str, expiration: int) -> _Certificate:
        subject = issuer = x509.Name([
            NameAttribute(NameOID.COUNTRY_NAME, country),
            NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        alternative_name = x509.SubjectAlternativeName([x509.DNSName(dns)])
        return x509.CertificateBuilder(
            subject_name=subject,
            issuer_name=issuer,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.datetime.utcnow(),
            not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=expiration),
            extensions=[x509.Extension(oid=alternative_name.oid, critical=False, value=alternative_name)]
        ).sign(private_key, hashes.SHA256(), default_backend())

    def generate_private_certificate(self) -> ssl.PrivateCertificate:
        private_key = self._generate_private_key()
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        certificate = self._generate_ssl_certificate(
            private_key, self.dns, self.country, self.organization, self.common_name, self.expiration
        )
        self.keyring.set_password(
            self.service_name, "server", private_key_bytes
        )
        self.keyring.set_password(
            self.service_name, "public", certificate.public_bytes(serialization.Encoding.PEM).decode()
        )
        return ssl.PrivateCertificate.loadPEM(
            "{}\n{}".format(private_key_bytes, certificate.public_bytes(serialization.Encoding.PEM).decode())
        )

    def get_private_certificate_from_keyring(self) -> ssl.PrivateCertificate:
        private_key = self.keyring.get_password("lbrynet", "server")
        x509_cert = self.keyring.get_password("lbrynet", "public")
        if private_key and x509_cert:
            return ssl.PrivateCertificate.loadPEM("{}\n{}".format(private_key, x509_cert))
        return self.generate_private_certificate()

    def get_ssl_context(self) -> SSLContext:
        cert_pem = self.keyring.get_password("lbrynet", "public")
        if cert_pem:
            return create_default_context(cadata=cert_pem)
