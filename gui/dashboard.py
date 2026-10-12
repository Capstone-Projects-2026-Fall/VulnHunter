# GUI Mockup Example, inspired by the Pi-hole dashboard layout

import sys
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QPlainTextEdit, QFrame, QAbstractItemView,
    QComboBox
)

from mock_data import DASHBOARD_STATS, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SAMPLE_REPOS

STYLE = """
QWidget { background-color: #0F172A; color: #E2E8F0; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QFrame#card { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; padding: 12px; }
QLabel#card_val { font-size: 26px; font-weight: bold; color: #38BDF8; background: transparent; }
QLabel#card_title { font-size: 12px; color: #94A3B8; background: transparent; }

/* Dropdown */
QComboBox { 
    background-color: #1E293B; 
    border: 1px solid #334155; 
    border-radius: 6px; 
    padding: 6px 12px; 
    color: #E2E8F0; 
    min-width: 220px;
}
QComboBox:hover { border: 1px solid #475569; }
QComboBox::drop-down { border: 0px; }
QComboBox QAbstractItemView { 
    background-color: #1E293B; 
    selection-background-color: #0284C7; 
    color: #E2E8F0; 
    border: 1px solid #334155; 
}

QPushButton { background-color: #334155; border: 1px solid #475569; border-radius: 6px; padding: 8px 16px; font-weight: 600; color: #F8FAFC; }
QPushButton:hover { background-color: #475569; }
QPushButton#btn_run { background-color: #0284C7; border: none; }
QPushButton#btn_run:hover { background-color: #0369A1; }
QPushButton#btn_fix { background-color: #16A34A; border: none; }
QPushButton#btn_fix:hover { background-color: #15803D; }
QPushButton#btn_verify { background-color: #9333EA; border: none; }
QPushButton#btn_verify:hover { background-color: #7E22CE; }

QTableWidget { background-color: #1E293B; border: 1px solid #334155; gridline-color: #334155; border-radius: 6px; }
QHeaderView::section { background-color: #0F172A; color: #94A3B8; border: none; padding: 8px; font-weight: bold; }
QPlainTextEdit { background-color: #020617; border: 1px solid #334155; border-radius: 6px; color: #38BDF8; font-family: Consolas, monospace; }
"""

class VulnHunterDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VulnHunter — Security Operations Dashboard")
        self.resize(1100, 750)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # 1. Pi-hole Style Stat Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)
        
        cards = [
            ("Repositories Scanned", str(DASHBOARD_STATS["repos_scanned"]), "#38BDF8"),
            ("Actionable Defects", str(DASHBOARD_STATS["total_findings"]), "#F87171"),
            ("Falsified & Disproven", str(DASHBOARD_STATS["falsified_flaws"]), "#FBBF24"),
            ("Verified Fixes", str(DASHBOARD_STATS["verified_fixes"]), "#4ADE80"),
        ]
        for title, val, color in cards:
            frame = QFrame()
            frame.setObjectName("card")
            card_vbox = QVBoxLayout(frame)
            lbl_val = QLabel(val)
            lbl_val.setObjectName("card_val")
            lbl_val.setStyleSheet(f"color: {color};")
            lbl_title = QLabel(title)
            lbl_title.setObjectName("card_title")
            card_vbox.addWidget(lbl_val)
            card_vbox.addWidget(lbl_title)
            stats_layout.addWidget(frame)
            
        main_layout.addLayout(stats_layout)

        # 2. Target Selection & Action Controls
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)

        repo_label = QLabel("Target Repository:")
        self.repo_dropdown = QComboBox()
        self.repo_dropdown.addItems(SAMPLE_REPOS)

        self.btn_run = QPushButton("Run Scanner (/vulnhunt)")
        self.btn_run.setObjectName("btn_run")
        self.btn_run.clicked.connect(self.simulate_run)

        self.btn_fix = QPushButton("Generate Fix (/vulnhunter-fix)")
        self.btn_fix.setObjectName("btn_fix")
        self.btn_fix.clicked.connect(lambda: self.log(f"[*] Simulated: Fix agent triggered for {self.repo_dropdown.currentText()}."))

        self.btn_verify = QPushButton("Verify Fix (/vulnhunt-fix-verify)")
        self.btn_verify.setObjectName("btn_verify")
        self.btn_verify.clicked.connect(lambda: self.log(f"[*] Simulated: Read-only verification agent executed for {self.repo_dropdown.currentText()}."))

        control_layout.addWidget(repo_label)
        control_layout.addWidget(self.repo_dropdown)
        control_layout.addWidget(self.btn_run)
        control_layout.addWidget(self.btn_fix)
        control_layout.addWidget(self.btn_verify)
        control_layout.addStretch()
        main_layout.addLayout(control_layout)

        # 3. Findings Table
        self.table = QTableWidget(len(SAMPLE_FINDINGS), 5)
        self.table.setHorizontalHeaderLabels(["Finding ID", "Severity", "Description", "Location", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        for row, item in enumerate(SAMPLE_FINDINGS):
            self.table.setItem(row, 0, QTableWidgetItem(item.id))
            self.table.setItem(row, 1, QTableWidgetItem(item.severity))
            self.table.setItem(row, 2, QTableWidgetItem(item.title))
            self.table.setItem(row, 3, QTableWidgetItem(f"{item.file_path}:{item.line}"))
            self.table.setItem(row, 4, QTableWidgetItem(item.status))

        main_layout.addWidget(self.table, 2)

        # 4. Console Output Feed
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setPlaceholderText("Agent execution logs will display here...")
        main_layout.addWidget(self.console, 1)

        # Demo Timer for output replay
        self.timer = QTimer()
        self.timer.timeout.connect(self._stream_output)
        self.log_idx = 0

    def log(self, text):
        self.console.appendPlainText(text)

    def simulate_run(self):
        selected_repo = self.repo_dropdown.currentText()
        self.console.clear()
        self.log(f"[*] Target selected: {selected_repo}")
        self.log_idx = 0
        self.btn_run.setEnabled(False)
        self.timer.start(350)

    def _stream_output(self):
        if self.log_idx < len(SAMPLE_OUTPUT):
            self.log(SAMPLE_OUTPUT[self.log_idx])
            self.log_idx += 1
        else:
            self.timer.stop()
            self.btn_run.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = VulnHunterDashboard()
    win.show()
    sys.exit(app.exec_())