#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Entry point cho PyInstaller - Build thành 1 file exe
File này được thiết kế để chạy độc lập, không sử dụng relative imports
"""
import sys
import os

def main():
    # Đảm bảo đường dẫn đúng khi chạy từ exe
    if getattr(sys, 'frozen', False):
        # Chạy từ PyInstaller bundle
        base_path = sys._MEIPASS
    else:
        # Chạy từ source
        base_path = os.path.dirname(os.path.abspath(__file__))
    
    # Thêm base_path vào sys.path
    if base_path not in sys.path:
        sys.path.insert(0, base_path)
    
    # Import và chạy ứng dụng
    from PyQt5.QtWidgets import QApplication
    from pcapqt.views.main_window import PcapQt
    
    app = QApplication(sys.argv)
    window = PcapQt()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
