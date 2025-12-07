import sys
import os

# Thêm đường dẫn package vào sys.path cho PyInstaller
if getattr(sys, 'frozen', False):
    # Nếu chạy từ exe (PyInstaller)
    application_path = os.path.dirname(sys.executable)
    sys.path.insert(0, application_path)
else:
    # Nếu chạy từ source
    application_path = os.path.dirname(os.path.abspath(__file__))

from PyQt5.QtWidgets import QApplication
from pcapqt.views.main_window import PcapQt

def main():
    app = QApplication(sys.argv)
    window = PcapQt()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()