from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES


def aes_encrypt():
    with open('C:\\Users\\amcsparron\\Desktop\\stick.png', 'rb') as f:
        b = f.read()

    mykey = b'Andrew McSparron'
    cipher = AES.new(mykey, AES.MODE_EAX)
    nonce = cipher.nonce
    enc_text, tag = cipher.encrypt_and_digest(b)
    print(enc_text)

    dec_cipher = AES.new(mykey, AES.MODE_EAX, nonce=nonce)
    print(dec_cipher.decrypt(enc_text))


class RSAKeyPairGenerator:
    def __init__(self, private_key_pass: str or None = None):
        if private_key_pass:
            self.__private_key_pass = bytes(private_key_pass, 'utf-8')
        else:
            self.__private_key_pass = None
        self.private_key_ins = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._valid_key_types = ['public', 'private']

    def _gen_private_key(self, key_password=None):
        if key_password:
            self.__private_key_pass = bytes(key_password, 'utf-8')
        else:
            pass
        if not self.__private_key_pass:
            unencrypted_pem_private_key = self.private_key_ins.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
            return unencrypted_pem_private_key
        else:
            encrypted_pem_private_key = self.private_key_ins.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.__private_key_pass))
            return encrypted_pem_private_key

    def _gen_public_key(self):
        pem_public_key = self.private_key_ins.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem_public_key

    def _write_key(self, output_path, key_type, **kwargs):
        private_key_pass = kwargs.get('private_key_pass', None)
        private_key_name = kwargs.get('private_key_name', 'private_key')
        public_key_name = kwargs.get('public_key_name', 'public_key')
        overwrite_existing = kwargs.get('overwrite_existing', False)
        output_path = Path(output_path)

        key_type = key_type.lower()
        if output_path.is_dir():
            pass
        else:
            try:
                output_path.mkdir(exist_ok=True)
            except FileNotFoundError:
                raise NotADirectoryError("output_path parent does not exist.") from None

        if key_type not in self._valid_key_types:
            raise ValueError(f"{key_type} is not a valid option")

        if key_type == 'private':
            private_full_path = Path(output_path, f'{private_key_name}.pem')
            if (private_full_path.is_file() and overwrite_existing) or not private_full_path.is_file():
                with open(private_full_path, 'w') as f:
                    f.write(self._gen_private_key(key_password=private_key_pass).decode())
            else:
                raise FileExistsError("file already exists, use overwrite_existing=True to overwrite.")

        elif key_type == 'public':
           public_full_path = Path(output_path, f'{public_key_name}.pub')
           if (public_full_path.is_file() and overwrite_existing) or not public_full_path.is_file():
               with open(public_full_path, 'w') as f:
                    f.write(self._gen_public_key().decode())
           else:
               raise FileExistsError("file already exists, use overwrite_existing=True to overwrite.")


        print(f"Wrote key to {f.name}")
        return f.name

    def gen_keypair(self, private_key_pass=None, **kwargs) -> (str, str):
        public_key_output_location = kwargs.get('public_key_output_location', 'C:\\Users\\amcsparron\\Desktop\\')
        private_key_output_location = kwargs.get('private_key_output_location', 'C:\\Users\\amcsparron\\Desktop\\')
        private_key_name = kwargs.get('private_key_name', 'private_key')
        public_key_name = kwargs.get('public_key_name', 'public_key')
        overwrite_existing = kwargs.get('overwrite_existing', False)

        if private_key_pass is None:
            private_key_pass = self.__private_key_pass
        else:
            pass

        private_key_location = self._write_key(output_path=private_key_output_location,
                                               key_type='private',
                                               private_key_pass=private_key_pass,
                                               private_key_name=private_key_name,
                                               overwrite_existing=overwrite_existing)
        public_key_location = self._write_key(output_path=public_key_output_location,
                                              key_type='public',
                                              public_key_pass=public_key_name,
                                              overwrite_existing=overwrite_existing)
        return private_key_location, public_key_location


class RSAEncrypterDecrypter:
    def __init__(self, **kwargs):
        self._private_key_location = kwargs.get('private_key_location', None)
        self._public_key_location = kwargs.get('public_key_location', None)
        self.__private_key_pass = kwargs.get('private_key_pass', None)


        if self._private_key_location is None and self._public_key_location is None:
            raise AttributeError("both public and private key location cannot be none")

        if self._private_key_location and Path(self._private_key_location).is_file():
            pass
        else:
            raise AttributeError(f"private key file could not be found at {self._private_key_location}")
        if self._public_key_location and Path(self._public_key_location).is_file():
            pass
        else:
            raise AttributeError(f"public key file could not be found at {self._public_key_location}")

        self._valid_key_types = ['public', 'private']
        self.__private_key = None
        self._public_key = None
        self.__serialized_private_key = None
        self._serialized_public_key = None

        if self._private_key_location:
            self.__private_key = self._load_key('private', private_key_pass=self.__private_key_pass)
        if self._public_key_location:
            self._public_key = self._load_key('public')

    def _load_key(self, key_type, **kwargs):
        enc_private_key_pass = kwargs.get('private_key_pass', None)
        if isinstance(enc_private_key_pass, str):
            enc_private_key_pass = bytes(enc_private_key_pass, 'utf-8')
        elif isinstance(enc_private_key_pass, bytes):
            pass
        elif not enc_private_key_pass:
            pass
        else:
            raise TypeError("enc_private_key_pass must be str or bytes")

        key_type = key_type.lower()
        if key_type not in self._valid_key_types:
            raise ValueError(f"{key_type} is not a valid option")
        else:
            pass
        if key_type == 'private':
            with open(self._private_key_location, 'rb') as f:
                key_info = f.read()
                self.__private_key = serialization.load_pem_private_key(key_info, enc_private_key_pass)
                return self.__private_key
        elif key_type == 'public':
            with open(self._public_key_location, 'rb') as f:
                key_info = f.read()
                self._public_key = serialization.load_pem_public_key(key_info)
                return self._public_key

    def serialize_key(self, key_type, **kwargs):
        enc_private_key_pass = kwargs.get('private_key_pass', b'')
        no_encrypt_private = kwargs.get('no_encrypt_private', False)
        key_type = key_type.lower()

        if isinstance(enc_private_key_pass, str):
            enc_private_key_pass = bytes(enc_private_key_pass, 'utf-8')
        elif isinstance(enc_private_key_pass, bytes):
            pass
        else:
            raise TypeError("enc_private_key_pass must be str or bytes")

        if key_type not in self._valid_key_types:
            raise ValueError(f"{key_type} is not a valid option")
        else:
            pass
        if key_type == 'private':
            if no_encrypt_private:
                serialized = self.__private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption())
            else:
                serialized = self.__private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(enc_private_key_pass))

            self.__serialized_private_key = serialized
            return self.__serialized_private_key.decode('utf-8')

        elif key_type == 'public':
            serialized = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self._serialized_public_key = serialized
            return self._serialized_public_key.decode('utf-8')

    def encrypt(self, message: str or bytes) -> str or bytes:
        use_private_key = False
        encrypted_message = None
        if self._public_key:
            pass
        elif self.__private_key:
            use_private_key = True
        else:
            raise AttributeError('Public key must be set before encrypting.')

        if isinstance(message, str):
            byte_message = bytes(message, 'utf-8')
        elif isinstance(message, bytes):
            byte_message = message
        else:
            raise AttributeError('Message must be str or bytes')
        if not use_private_key:  # this is the default
            encrypted_message = self._public_key.encrypt(byte_message,
                                                         padding.OAEP(mgf=padding.MGF1(
                                                             algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(),
                                                             label=None)
                                                         )
        elif use_private_key:
            encrypted_message = self.__private_key.encrypt(byte_message,
                                                           padding.OAEP(mgf=padding.MGF1(
                                                               algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(),
                                                               label=None)
                                                           )
        return encrypted_message

    def decrypt(self, encrypted_message, return_as_bytes=False):
        decrypted_bytes = self.__private_key.decrypt(encrypted_message,
                                                     padding=padding.OAEP(
                                                         mgf=padding.MGF1(
                                                             algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(),
                                                         label=None)
                                                     )
        if return_as_bytes:
            return decrypted_bytes
        elif not return_as_bytes:
            return decrypted_bytes.decode('utf-8')

if __name__ == '__main__':
    key_dir = Path('../Misc_Project_Files/keys')
    private_key_path = key_dir.joinpath('private_key.pem')
    public_key_path = key_dir.joinpath('public_key.pub')

    if private_key_path.is_file() and public_key_path.is_file():
        pass
    else:
        GenKey = RSAKeyPairGenerator()
        private_key_path, public_key_path = GenKey.gen_keypair(public_key_output_location=key_dir,
                                                               private_key_output_location=key_dir,
                                                               private_key_pass='password', overwrite_existing=False)

    EnDe = RSAEncrypterDecrypter(private_key_location=key_dir.joinpath('private_key.pem'),
                                 public_key_location=key_dir.joinpath('public_key.pub'),
                                 private_key_pass='password')