import os
import sys
from PIL.ImageQt import ImageQt
from PyQt5.QtGui import QIcon, QPixmap, QImage
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QGridLayout, QPushButton, QDialogButtonBox, QLabel,
    QInputDialog, QLineEdit, QMessageBox
)

class OTPUi(QDialog):
    """
    OTP Manager GUI
    """
    def __init__(self, icon_path=None, parent=None):
        if icon_path == None:
            self._icon_path = sys.path[0] + '/icons'
        else:
            self._icon_path = icon_path
        super(OTPUi, self).__init__(parent)
        self.setWindowTitle("OTP Manager")
        self._mainLayout = QVBoxLayout()
        self._otpLayout = QGridLayout()
        self._mainLayout.addLayout(self._otpLayout)
        self.logoutBtn = QPushButton()
        self.logoutBtn.setIcon(QIcon(os.path.join(self._icon_path, "sign-out-alt-solid.svg")))
        self.logoutBtn.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        self.addBtn = QPushButton()
        self.addBtn.setIcon(QIcon(os.path.join(self._icon_path, "plus-square-solid.svg")))
        self.addBtn.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        buttonBox = QDialogButtonBox()
        buttonBox.addButton(self.addBtn, QDialogButtonBox.ActionRole)
        buttonBox.addButton(self.logoutBtn, QDialogButtonBox.ActionRole)
        buttonBox.setCenterButtons(True)
        self._mainLayout.addWidget(buttonBox)
        self.setLayout(self._mainLayout)
        self.rows = {}

    def createRow(self, account):
        accountLabel = QLabel(account, alignment=Qt.AlignLeft)
        otpLabel = QLabel("", alignment=Qt.AlignCenter)
        otpLabel.setTextInteractionFlags(Qt.TextSelectableByMouse)
        showBtn = QPushButton()
        showBtn.setIcon(QIcon(os.path.join(self._icon_path, "qrcode-solid.svg")))
        showBtn.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        deleteBtn = QPushButton()
        deleteBtn.setIcon(QIcon(os.path.join(self._icon_path, "trash-alt-solid.svg")))
        deleteBtn.setStyleSheet("background-color: rgba(255, 255, 255, 0);")
        widgets = {
            "accountLabel": accountLabel, "otpLabel": otpLabel,
            "showBtn": showBtn, "deleteBtn": deleteBtn
        }
        self.rows[account] = widgets
        i = len(self.rows)
        for n, widget in enumerate(widgets.values()):
            self._otpLayout.addWidget(widget, i, n)
        return widgets

    def setOTPs(self, data):
        """
        Refresh time-based one-time passwords for all accounts
        """
        for account, otp in data.items():
            try:
                label = self.rows[account]
            except KeyError:
                label = self._createRow(account)
            label["otpLabel"].setText(otp)

    def getPassword(self):
        """
        Show dialog box to get password from user
        """
        text, ok = QInputDialog.getText(
            self, "OTP Manager", "Enter password:",
            QLineEdit.Password
        )
        if ok:
            return text
        else:
            return False

    def getNewPassword(self):
        """
        Show dialog box to get new password from user
        """
        text, ok = QInputDialog.getText(
            self, "OTP Manager", "Enter new password:",
            QLineEdit.Password
        )
        if ok:
            return text
        else:
            return False

    def getConfirmation(self):
        msg = QMessageBox()
        msg.setText("Are you sure?")
        msg.setIcon(QMessageBox.Warning)
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        if msg.exec() == QMessageBox.Ok:
            return True

    def showQRCode(self, qrcode):
        """
        Display OTP key as QR code
        """
        msg = QDialog()
        imageLabel = QLabel()
        # convert PIL image to Qt format
        qim = ImageQt(qrcode)
        imageLabel.setPixmap(QPixmap.fromImage(qim));
        layout = QVBoxLayout()
        layout.addWidget(imageLabel)
        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
        buttonBox.accepted.connect(msg.accept)
        layout.addWidget(buttonBox)
        msg.setLayout(layout)
        msg.exec()

    def showKey(self, key):
        """
        Display OTP key as text
        """
        msg = QMessageBox()
        msg.setText(key)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec()

    def removeAccount(self, account):
        """
        Remove account from UI
        """
        for w in self.rows[account].values():
            self._otpLayout.removeWidget(w)
            w.deleteLater()
        del(self.rows[account])

    def getNewAccount(self):
        """
        Show dialog box to get new account details
        """
        form = addAccountForm()
        if form.exec():
            return {"account": form.account.text(), "key": form.token.text()}
        else:
            return None

class addAccountForm(QDialog):
    def __init__(self, parent=None):
        super(addAccountForm, self).__init__(parent)
        self.setWindowTitle("OTP Manager")
        # Create widgets
        self.accountLabel = QLabel("Account:")
        self.account = QLineEdit()
        self.tokenLabel = QLabel("TOTP key:")
        self.token = QLineEdit()
        buttons = QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        self.buttonBox = QDialogButtonBox(buttons)
        # Connect signals
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        # Create layout and add widgets
        layout = QVBoxLayout()
        layout.addWidget(self.accountLabel)
        layout.addWidget(self.account)
        layout.addWidget(self.tokenLabel)
        layout.addWidget(self.token)
        layout.addWidget(self.buttonBox)
        # Set dialog layout
        self.setLayout(layout)
