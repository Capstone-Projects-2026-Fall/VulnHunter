import sys
from pathlib import Path

from PyQt6 import uic
from PyQt6.QtWidgets import QApplication, QMainWindow

UI_FILE = Path(__file__).resolve().parent / "vulnhunter_ui_opt1.ui"
#UI_FILE = Path(__file__).resolve().parent / "vulnhunter_ui_opt2.ui"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi(UI_FILE, self)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()