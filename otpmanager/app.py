import sys
from PySide6.QtWidgets import QApplication
from otpmanager.view import OTPUi
from otpmanager.model import OTPModel
from otpmanager.ctrl import OTPCtrl

def run():
    app = QApplication([])
    view = OTPUi(sys.path[0] + '/icons')
    view.show()
    model = OTPModel(sys.path[0]+'/.otp_master_key', sys.path[0]+'/.otp_keys',
        b'\xe9K\x0b\x9dx\r\xe0\xdd:\x91\xfa\x8dP\xbat\x97')
    controller = OTPCtrl(model=model, view=view)
    sys.exit(app.exec_())
