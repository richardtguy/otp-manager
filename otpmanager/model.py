import json
import os
import sys
from base64 import urlsafe_b64encode, b32decode
import binascii
from time import time
import qrcode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.fernet import Fernet, InvalidToken

class OTPError(Exception):
    """Base class for exceptions"""
    pass

class MissingKeyFileError(OTPError):
    """Exception raised if key file is missing"""
    def __init__(self, message):
        self.message = message

class OTPModel():
    """
    OTP Manager Model
    """
    def __init__(self, master_key_path, keyfile_path, salt):
        self.keyfile_path = keyfile_path
        self.master_key_path = master_key_path
        self.salt = salt
        self._master_key = self._get_master_key()

    def _get_master_key(self, password=None):
        """
        Return saved master key if available, or use password
        """
        # Retrieve key from file if available
        if password==None:
            try:
                with open(self.master_key_path, 'rb') as f:
                    master_key = f.read()
                    # Or get from user input
            except FileNotFoundError:
                return None
            return master_key
        else:
            kdf = PBKDF2HMAC(
                algorithm=SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )
            master_key = urlsafe_b64encode(kdf.derive(password.encode()))
            # save master key to file
            with open(self.master_key_path, 'wb') as f:
                f.write(master_key)
            return master_key

    def _load_otp_keys(self):
        """
        Load and decrypt account names and OTP keys from file
        """
        try:
            with open(self.keyfile_path, 'rb') as f:
                encrypted = f.read()
        except FileNotFoundError as exc:
            raise MissingKeyFileError("Missing key file") from exc
        master_key = self._master_key
        if master_key ==  None:
            return None
        fernet = Fernet(master_key)
        try:
            decrypted = fernet.decrypt(encrypted).decode()
        except InvalidToken:
            return None
        return json.loads(decrypted)

    def _save_otp_keys(self):
        datab = json.dumps(self._otp_keys).encode()
        fernet = Fernet(self._get_master_key())
        encrypted = fernet.encrypt(datab)
        with open(self.keyfile_path, 'wb') as f:
            f.write(encrypted)

    @property
    def verified(self):
        self._otp_keys = self._load_otp_keys()
        if self._otp_keys or self._otp_keys == {}:
            self._verified = True
        else:
            self._verified = False
        return self._verified

    def get_otp_keys(self):
        if self.verified:
            return self._otp_keys
        else:
            return None

    def verify_with_password(self, password):
        self._master_key = self._get_master_key(password)

    def logout(self):
        os.remove(self.master_key_path)

    def create_key_file(self, password):
        self.logout()
        self._otp_keys = {}
        self.verify_with_password(password)
        self._save_otp_keys()

    def get_otps(self):
        otps = {}
        for account, key in self._otp_keys.items():
            missing_padding = len(key) % 8
            if missing_padding != 0:
                key += '=' * (8 - missing_padding)
            try:
                byte_key = b32decode(key, casefold=True)
            except binascii.Error:
                otps[account] = None
                break
            totp = TOTP(
                byte_key,
                6,
                SHA1(),
                30,
                backend=default_backend(),
                enforce_key_length=False
            )
            otp = totp.generate(time()).decode()
            otps[account] = otp
        return otps

    def add_otp_key(self, data):
        self._otp_keys[data["account"]] = data["key"].replace(" ","")
        self._save_otp_keys()

    def del_otp_key(self, account):
        self._otp_keys.pop(account)
        self._save_otp_keys()

    def get_key(self, account):
        """
        Return the TOTP key for the account as plain text
        """
        return self._otp_keys[account]

    def get_qrcode(self, account):
        """
        Return a PIL image of QR code encoding the OTP Auth URI for the account
        """
        uri = f"otpauth://totp/{account}?secret={self._otp_keys[account]}"
        img = qrcode.make(uri)
        return img
