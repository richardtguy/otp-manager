from functools import partial
from PySide6.QtCore import QTimer

from otpmanager.model import MissingKeyFileError

class OTPCtrl():
    """
    OTP Manager Controller
    """
    def __init__(self, model, view):
        self._model = model
        self._view = view
        # authenticate
        try:
            while not self._model.verified:
                self._model.verify_with_password(self._view.getPassword())
        except MissingKeyFileError:
            new_password = self._view.getNewPassword()
            if new_password:
                # create new key file and encrypt with new password
                self._model.create_key_file(new_password)
            else:
                self._view.close()
        # populate UI with initial data
        for account, key in self._model.get_otp_keys().items():
            self._createRow(account, key)
        self._updateOTPs()
        # connect timer to refresh display
        self._connectTimers()
        # connect signals and slots
        self._view.logoutBtn.clicked.connect(self._logout)
        self._view.addBtn.clicked.connect(self._addAccount)

    def _createRow(self, account, key):
        self._view.createRow(account)
        self._view.rows[account]["showBtn"].clicked.connect(
            partial(self._showQRCode, account))
        self._view.rows[account]["deleteBtn"].clicked.connect(
            partial(self._deleteAccount, account))

    def _updateOTPs(self):
        self._view.setOTPs(self._model.get_otps())

    def _logout(self):
        self._model.logout()
        self._view.close()

    def _addAccount(self):
        new_account = self._view.getNewAccount()
        if new_account:
            self._model.add_otp_key(new_account)
            self._createRow(new_account['account'], new_account['key'])

    def _showQRCode(self, account):
        qrcode = self._model.get_qrcode(account)
        self._view.showQRCode(qrcode)

    def _deleteAccount(self, account):
        if self._view.getConfirmation():
            self._model.del_otp_key(account)
            self._view.removeAccount(account)

    def _connectTimers(self):
        self._timer = QTimer()
        self._timer.timeout.connect(self._updateOTPs)
        self._timer.start(1000)
