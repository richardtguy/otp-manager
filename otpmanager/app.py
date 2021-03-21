import sys
from PyQt5.QtWidgets import QApplication
from otpmanager.view import OTPUi
from otpmanager.model import OTPModel
from otpmanager.ctrl import OTPCtrl

def run():
    app = QApplication([])
    view = OTPUi()
    view.show()
    model = OTPModel()
    controller = OTPCtrl(model=model, view=view)
    sys.exit(app.exec_())
