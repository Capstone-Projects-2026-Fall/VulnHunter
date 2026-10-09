import sys
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QWidget,
)

from mock_data import SAMPLE_FINDINGS, SAMPLE_OUTPUT, ScanRecord


STYLE = """
QWidget { color: #EDE6EA; font-size: 14px; }
QMainWindow, QWidget#root { background: #15121A; }
QDialog, QMessageBox { background: #1F1A24; }
QFrame#header { background: #4A1424; border: 0; border-bottom: 1px solid #8B1E3F; }
QPushButton#home {
    background: transparent; border: 0; color: #FFFFFF; font-size: 20px;
    font-weight: 600; padding: 0 12px;
}
QLabel#title { font-size: 24px; font-weight: 600; }
QCheckBox { background: transparent; }
QLineEdit, QComboBox {
    background: #1F1A24; border: 1px solid #4A3B52; border-radius: 5px; padding: 8px 10px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #B04A68; }
QComboBox QAbstractItemView {
    background: #1F1A24; color: #EDE6EA; selection-background-color: #5A1F35;
    selection-color: #FFFFFF; border: 1px solid #4A3B52;
}
QPushButton {
    background: #2A2230; border: 1px solid #4A3B52; border-radius: 5px; padding: 9px 22px;
}
QPushButton:hover { background: #352B3D; }
QPushButton:disabled { color: #7E7280; background: #221C28; }
QPushButton#primary { background: #8B1E3F; color: #FFFFFF; border: 0; font-weight: 600; }
QPushButton#primary:hover { background: #A32850; }
QPushButton#primary:disabled { background: #4A2432; color: #9A8590; }
QTableWidget {
    background: #1F1A24; border: 1px solid #3A2F40; gridline-color: #332A3A;
    selection-background-color: #5A1F35; selection-color: #FFFFFF;
}
QHeaderView::section { background: #2A2230; border: 0; padding: 9px 12px; font-weight: 600; }
QPlainTextEdit { background: #100D14; border: 1px solid #3A2F40; color: #D8C9D0; }
QScrollBar:vertical { background: #1F1A24; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #4A3B52; border-radius: 5px; min-height: 24px; }
QScrollBar:horizontal { background: #1F1A24; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #4A3B52; border-radius: 5px; min-width: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
"""


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return table


class HistoryPage(QWidget):
    new_scan = pyqtSignal()
    record_selected = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        title = QLabel("Scans")
        title.setObjectName("title")
        new_btn = QPushButton("New Scan")
        new_btn.setObjectName("primary")
        new_btn.clicked.connect(lambda: self.new_scan.emit())

        top = QHBoxLayout()
        top.addWidget(title)
        top.addStretch()
        top.addWidget(new_btn)

        self.table = make_table(["Repository", "Model", "Mode", "Date", "Findings"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 90)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 100)
        self.table.cellClicked.connect(lambda row, _col: self.record_selected.emit(row))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addWidget(self.table, 1)

    def refresh(self, records):
        self.table.setRowCount(len(records))
        for row, rec in enumerate(records):
            values = [rec.repo, rec.model, rec.mode, rec.date, str(len(rec.findings))]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))


class ScanPage(QWidget):
    finished = pyqtSignal(object)  # emits a ScanRecord

    def __init__(self, sample_findings, sample_output):
        super().__init__()
        self.sample_findings = sample_findings
        self.sample_output = sample_output
        self._line_index = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._next_line)

        # Top row: repository, model, demo, scan
        self.repo = QLineEdit()
        self.repo.setPlaceholderText("GitHub URL or local path")
        self.model_box = QComboBox()
        self.model_box.addItems(["Claude Opus", "OpenAI", "Gemini"])
        for i in (1, 2):
            self.model_box.model().item(i).setEnabled(False)
        self.demo = QCheckBox("Demo")
        self.demo.setChecked(True)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.start_scan)

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.repo, 1)
        top.addWidget(self.model_box)
        top.addWidget(self.demo)
        top.addWidget(self.scan_btn)

        # Findings table
        self.table = make_table(["ID", "Severity", "Finding", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(3, 120)
        self.table.itemSelectionChanged.connect(self._update_buttons)

        # Actions
        self.fix_btn = QPushButton("Fix")
        self.fix_btn.setObjectName("primary")
        self.verify_btn = QPushButton("Verify")
        self.report_btn = QPushButton("Report")
        actions = QHBoxLayout()
        actions.setSpacing(10)
        for btn in (self.fix_btn, self.verify_btn, self.report_btn):
            btn.clicked.connect(lambda _checked, b=btn: self._not_implemented(b.text()))
            actions.addWidget(btn)
        actions.addStretch()

        # Output
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addWidget(self.table, 2)
        layout.addLayout(actions)
        layout.addWidget(self.output, 1)

        self._update_buttons()

    # Page states
    def reset(self):
        """Blank page for a new scan."""
        self.timer.stop()
        self._set_inputs_editable(True)
        self.repo.clear()
        self.demo.setChecked(True)
        self.table.setRowCount(0)
        self.output.clear()
        self._update_buttons()

    def show_record(self, record):
        """Read-only view of a past scan."""
        self.timer.stop()
        self.repo.setText(record.repo)
        self.demo.setChecked(record.mode == "Demo")
        self._fill_table(record.findings)
        self.output.setPlainText("\n".join(record.output))
        self._set_inputs_editable(False)

    def _set_inputs_editable(self, editable):
        self.repo.setReadOnly(not editable)
        self.model_box.setEnabled(editable)
        self.demo.setEnabled(editable)
        self.scan_btn.setEnabled(editable)

    # Scan (demo replay only)
    def start_scan(self):
        if not self.demo.isChecked():
            self.output.setPlainText("Live scan is not implemented yet.")
            return
        self.table.setRowCount(0)
        self.output.clear()
        self.scan_btn.setEnabled(False)
        self._line_index = 0
        self.timer.start(500)

    def _next_line(self):
        if self._line_index < len(self.sample_output):
            self.output.appendPlainText(self.sample_output[self._line_index])
            self._line_index += 1
            return
        self.timer.stop()
        self._fill_table(self.sample_findings)
        self.scan_btn.setEnabled(True)
        now = datetime.now()
        record = ScanRecord(
            repo=self.repo.text().strip() or "(none)",
            model=self.model_box.currentText(),
            mode="Demo",
            date=f"{now:%b} {now.day}, {now.year}",
            findings=list(self.sample_findings),
            output=list(self.sample_output),
        )
        self.finished.emit(record)

    def _fill_table(self, findings):
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            for col, value in enumerate([f.id, f.severity, f.title, f.status]):
                self.table.setItem(row, col, QTableWidgetItem(value))
        if findings:
            self.table.selectRow(0)

    def _update_buttons(self):
        has_selection = bool(self.table.selectionModel().selectedRows())
        for btn in (self.fix_btn, self.verify_btn, self.report_btn):
            btn.setEnabled(has_selection)

    def _not_implemented(self, name):
        QMessageBox.information(self, "VulnHunter", f"{name} is not implemented yet.")


class MainWindow(QMainWindow):
    HISTORY, SCAN = 0, 1

    def __init__(self):
        super().__init__()
        self.setWindowTitle("VulnHunter")
        self.resize(960, 620)
        self.history = []  # newest first; held in memory only

        self.history_page = HistoryPage()
        self.scan_page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.history_page)
        self.stack.addWidget(self.scan_page)

        # Shared header: one home button, centered, visible on every page
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(56)
        home = QPushButton("VulnHunter")
        home.setObjectName("home")
        home.setCursor(Qt.PointingHandCursor)
        home.clicked.connect(self.show_history)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)
        header_layout.addStretch()
        header_layout.addWidget(home)
        header_layout.addStretch()

        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.history_page.new_scan.connect(self.new_scan)
        self.history_page.record_selected.connect(self.open_record)
        self.scan_page.finished.connect(self.add_record)

    def show_history(self):
        self.stack.setCurrentIndex(self.HISTORY)

    def new_scan(self):
        self.scan_page.reset()
        self.stack.setCurrentIndex(self.SCAN)

    def open_record(self, row):
        self.scan_page.show_record(self.history[row])
        self.stack.setCurrentIndex(self.SCAN)

    def add_record(self, record):
        self.history.insert(0, record)
        self.history_page.refresh(self.history)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
