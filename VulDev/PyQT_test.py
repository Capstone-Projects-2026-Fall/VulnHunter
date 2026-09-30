import sys
import os
import subprocess

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QPushButton,
    QLineEdit,
    QTextEdit
)

# Keep track of the directory
current_directory = os.getcwd()


def run_ls():
    result = subprocess.run(
        ["ls"],
        cwd=current_directory,
        capture_output=True,
        text=True
    )

    output_box.setText(result.stdout)

def run_pwd():
    result = subprocess.run(
        ["pwd"],
        cwd=current_directory,
        capture_output=True,
        text=True
    )
    output_box.setText(result.stdout)

def run_cd():
    global current_directory

    path = cd_input.text()

    new_directory = os.path.abspath(
        os.path.join(current_directory, path)
    )

    if os.path.isdir(new_directory):
        current_directory = new_directory
        output_box.setText(
            f"Current directory:\n{current_directory}"
        )
    else:
        output_box.setText(
            f"Directory not found:\n{new_directory}"
        )


# Create PyQt application
app = QApplication(sys.argv)
app.setFont(QFont("Times New Roman", 20)) 

window = QWidget()
window.setWindowTitle("VULDEV PyQT Test")
window.resize(600, 500)

layout = QVBoxLayout()

# ls button
ls_button = QPushButton("ls")
ls_button.setMinimumHeight(50)
ls_button.clicked.connect(run_ls)

# pwd button
pwd_button = QPushButton("pwd")
pwd_button.setMinimumHeight(50)
pwd_button.clicked.connect(run_pwd)

# cd input
cd_input = QLineEdit()
cd_input.setMinimumHeight(50)
cd_input.setPlaceholderText("Enter directory (e.g. Documents)")

# cd button
cd_button = QPushButton("cd")
cd_button.setMinimumHeight(50)
cd_button.clicked.connect(run_cd)

# Output
output_box = QTextEdit()
output_box.setMinimumHeight(250)
output_box.setReadOnly(True)

# Add everything to the window
layout.addWidget(ls_button)
layout.addWidget(pwd_button)
layout.addWidget(cd_input)
layout.addWidget(cd_button)
layout.addWidget(output_box)

window.setLayout(layout)
window.show()

sys.exit(app.exec())