import re
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path

# main_gui.py is in VulnHunter/gui/, so the repo root is one level up
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QSizePolicy,
)

from gui.data.mock_data import (
    ACCEPT_REASONS, DISABLED_MODELS, IGNORE_REASONS, MODEL_IDS, REPO_URL, SAMPLE_FINDINGS,
    SAMPLE_OUTPUT, SEED_HISTORY, SEVERITY_ORDER, ScanRecord, code_url, sample_fix,
    sample_snippet, split_location,
)
from llm_connector.conn_all_llm import LLMConnector
from gui.api_conn_page import ApiConnectorPage

STYLE = """
QWidget { color: #E6EEF8; font-size: 18px; }
QMainWindow, QWidget#root { background: #0A1424; }
QDialog, QMessageBox { background: #111E33; }
QFrame#header { background: #0F2747; border: 0; border-bottom: 1px solid #1F4E8C; }
QFrame#card { background: #111E33; border: 1px solid #243B5C; border-radius: 5px; }
QFrame#card QLabel { background: transparent; }
QLabel#severityHeading { font-size: 12px; font-weight: 600; }
QLabel#severityHeadline { font-size: 18px; font-weight: 600; }
QLabel#severityDetail { font-size: 11px; }
QLabel#homeTitle, QLabel#statsTitle { font-size: 32px; font-weight: 600; }
QLabel#cardValue { font-size: 18px; font-weight: 600; }
QPushButton#home {
    background: transparent; border: 0; color: #E6EEF8; font-size: 20px;
    font-weight: 600; padding: 0 12px;
}
QPushButton#backNavigation, QPushButton#forwardNavigation {
    background: transparent; border: 0; color: #E6EEF8;
    font-size: 34px; padding: 0; min-width: 32px; max-width: 32px;
}
QPushButton#backNavigation:hover, QPushButton#forwardNavigation:hover {
    color: #38BDF8;
}
QPushButton#backNavigation:disabled, QPushButton#forwardNavigation:disabled {
    color: #52647B; background: transparent;
}
QLabel#title { font-size: 24px; font-weight: 600; }
QWidget#homePage QLabel#homeTitle { font-size: 60px; font-weight: 600; }
QWidget#homePage QLabel#homeSubtitle { font-size: 28px; color: #9FB3CC; }
QWidget#homePage QPushButton { font-size: 26px; padding: 16px 44px; }
QLabel#muted { color: #7F93AD; }
QPushButton#link {
    background: transparent; border: 0; padding: 0; color: #38BDF8; text-decoration: underline;
}
QPushButton#link:hover { color: #7DD3FC; }
QCheckBox { background: transparent; }
QLineEdit, QComboBox {
    background: #111E33; border: 1px solid #243B5C; border-radius: 5px; padding: 8px 10px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #38BDF8; }
QComboBox QAbstractItemView {
    background: #111E33; color: #E6EEF8; selection-background-color: #1B4B7A;
    selection-color: #E6EEF8; border: 1px solid #243B5C;
}
QPushButton {
    background: #111E33; border: 1px solid #243B5C; border-radius: 5px; padding: 9px 22px;
}
QPushButton:hover { background: #172A47; }
QPushButton:disabled { color: #7F93AD; background: #0A1424; }
QPushButton#primary { background: #38BDF8; color: #05101F; border: 0; font-weight: 600; }
QPushButton#primary:hover { background: #7DD3FC; }
QPushButton#primary:disabled { background: #243B5C; color: #7F93AD; }
QTableWidget {
    background: #111E33; border: 1px solid #243B5C; gridline-color: #243B5C;
    selection-background-color: #1B4B7A; selection-color: #E6EEF8;
}
QHeaderView::section { background: #172A47; border: 0; padding: 9px 12px; font-weight: 600; }
QPlainTextEdit {
    background: #08101D; border: 1px solid #243B5C; color: #E6EEF8;
    font-family: Consolas; font-size: 10px;
}
QScrollBar:vertical { background: #111E33; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #243B5C; border-radius: 5px; min-height: 24px; }
QScrollBar:horizontal { background: #111E33; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: #243B5C; border-radius: 5px; min-width: 24px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
"""


MIN_WINDOW_SIZE = (1300, 700)
PREFERRED_WINDOW_SIZE = (1360, 920)


def default_window_size(screen_width, screen_height):
    """Preferred size, shrunk to fit the available screen but never below the minimum."""
    width = min(PREFERRED_WINDOW_SIZE[0], int(screen_width * 0.95))
    height = min(PREFERRED_WINDOW_SIZE[1], int(screen_height * 0.92))
    return max(width, MIN_WINDOW_SIZE[0]), max(height, MIN_WINDOW_SIZE[1])


def scaled_stylesheet(stylesheet, scale):
    return re.sub(
        r"(?<![\w.-])(\d+(?:\.\d+)?)px\b",
        lambda match: f"{round(float(match.group(1)) * scale)}px",
        stylesheet,
    )


def zoom_stylesheet(scale):
    stylesheet = scaled_stylesheet(STYLE, scale)
    return (
        f"{stylesheet}\n"
        "QPushButton#home { font-size: 20px; }\n"
        f"QTableWidget {{ font-size: {round(18 * scale)}px; }}\n"
        f"QHeaderView::section {{ font-size: {round(18 * scale)}px; }}"
    )


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setWordWrap(True)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return table


class SeverityTracker(QFrame):
    """Side panel with one count per severity tier; the top two tiers are the headline rows."""
    HEADLINE_TIERS = 2

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self.setFixedWidth(200)
        box = QVBoxLayout(self)
        heading = QLabel("Severity")
        heading.setObjectName("severityHeading")
        box.addWidget(heading)
        self.counts = {}
        for i, name in enumerate(SEVERITY_ORDER):
            headline = i < self.HEADLINE_TIERS
            label = QLabel(name)
            count = QLabel("0")
            label.setObjectName("severityHeadline" if headline else "severityDetail")
            count.setObjectName("severityHeadline" if headline else "severityDetail")
            if headline:
                count.setStyleSheet("color: #38BDF8;")
            row = QHBoxLayout()
            row.addWidget(label)
            row.addStretch()
            row.addWidget(count)
            box.addLayout(row)
            self.counts[name] = count
        box.addStretch()

    def update_counts(self, findings):
        for name, label in self.counts.items():
            label.setText(str(sum(f.severity == name for f in findings)))

HOME_QSS = """
#homePage {
    background: #0a1424;
    font-family: "Segoe UI Variable Display", "Segoe UI", "Inter", sans-serif;
}
#homePage QLabel { background: transparent; }

#homeEyebrow { font-size: 12px; font-weight: 700; letter-spacing: 3px; color: #38bdf8; }
#homeHeading { font-size: 38px; font-weight: 700; color: #f1f6fd; }
#homeSub     { font-size: 15px; color: #9fb4d0; }
#homeFooter  { font-size: 12px; color: #4d6585; }

/* status pill */
#statusPill {
    font-size: 12px; font-weight: 700;
    padding: 7px 14px; border-radius: 14px;
    background: #0d2646; border: 1px solid #16365f; color: #9fb4d0;
}
#statusPill[state="ok"]  { color: #4ade80; border-color: #1f5f3f; background: rgba(74,222,128,0.08); }
#statusPill[state="off"] { color: #fbbf24; border-color: #5f4a1f; background: rgba(251,191,36,0.08); }

/* module cards */
#moduleCard {
    background: #0d2646; border: 1px solid #16365f;
    border-radius: 14px; text-align: left;
}
#moduleCard:hover   { background: #123560; border: 1px solid #38bdf8; }
#moduleCard:pressed { background: #0a1f3a; }
#homePage QLabel#cardIcon {
    font-family: "Segoe UI Symbol", "Segoe UI";
    font-size: 24px; color: #38bdf8;
    background: rgba(56,189,248,0.12); border-radius: 12px;
}
#cardTitle { font-size: 22px; font-weight: 700; color: #f1f6fd; }
#cardDesc  { font-size: 14px; color: #9fb4d0; }
#cardGo    { font-size: 14px; font-weight: 700; color: #38bdf8; }

/* getting started panel */
#panel { background: #0d2646; border: 1px solid #16365f; border-radius: 12px; }
#panelTitle { font-size: 12px; font-weight: 700; letter-spacing: 2px; color: #7b93b3; }
#homePage QLabel#stepBadge {
    font-size: 12px; font-weight: 700; color: #0a1424;
    background: #38bdf8; border-radius: 12px;
}
#stepText { font-size: 14px; color: #dbe6f5; }
"""


class ModuleCard(QPushButton):
    """A large clickable module card."""

    def __init__(self, icon: str, title: str, description: str):
        super().__init__()
        self.setObjectName("moduleCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        ic = QLabel(icon)
        ic.setObjectName("cardIcon")
        ic.setFixedSize(52, 52)
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)

        t = QLabel(title)
        t.setObjectName("cardTitle")
        d = QLabel(description)
        d.setObjectName("cardDesc")
        d.setWordWrap(True)
        go = QLabel("Open  →")
        go.setObjectName("cardGo")

        for w in (ic, t, d, go):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 24, 26, 22)
        lay.setSpacing(0)
        lay.addWidget(ic, 0, Qt.AlignmentFlag.AlignLeft)
        lay.addStretch()
        lay.addWidget(t)
        lay.addSpacing(8)
        lay.addWidget(d)
        lay.addSpacing(16)
        lay.addWidget(go)

class HomePage(QWidget):
    dashboard_requested = pyqtSignal()
    stats_requested = pyqtSignal()
    connector_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("homePage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(HOME_QSS)

        # ---------- header ----------
        eyebrow = QLabel("OVERVIEW")
        eyebrow.setObjectName("homeEyebrow")
        heading = QLabel("Welcome back")
        heading.setObjectName("homeHeading")
        sub = QLabel("Review findings, track stats, or connect a data source.")
        sub.setObjectName("homeSub")

        titles = QVBoxLayout()
        titles.setSpacing(0)
        titles.addWidget(eyebrow)
        titles.addSpacing(8)
        titles.addWidget(heading)
        titles.addSpacing(6)
        titles.addWidget(sub)

        self.pill = QLabel()
        self.pill.setObjectName("statusPill")
        self.set_api_status(False)

        header = QHBoxLayout()
        header.addLayout(titles)
        header.addStretch()
        header.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignTop)

        # ---------- module cards ----------
        cards = QHBoxLayout()
        cards.setSpacing(20)
        for icon, title, desc, signal in [
            ("▦", "Dashboard", "Review findings and scan activity in one place.", self.dashboard_requested),
            ("◔", "Stats", "Totals and charts across all of your results.", self.stats_requested),
            ("⇄", "API Connector", "Configure and test your data source connections.", self.connector_requested),
        ]:
            card = ModuleCard(icon, title, desc)
            card.clicked.connect(signal.emit)
            cards.addWidget(card, 1)

        # ---------- getting started (full width, steps in a row) ----------
        panel = QFrame()
        panel.setObjectName("panel")
        panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        panel_lay = QVBoxLayout(panel)
        panel_lay.setContentsMargins(24, 18, 24, 20)
        panel_lay.setSpacing(14)

        panel_title = QLabel("GETTING STARTED")
        panel_title.setObjectName("panelTitle")
        panel_lay.addWidget(panel_title)

        steps = QHBoxLayout()
        steps.setSpacing(32)
        for n, text in enumerate(
            ["Connect your API", "Go to dashboard", "Utilize Vulnhunter"], 1
        ):
            steps.addLayout(self._step_row(str(n), text), 1)
        panel_lay.addLayout(steps)

    

        # ---------- assemble ----------
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 36, 48, 20)
        layout.setSpacing(0)
        layout.addLayout(header)
        layout.addSpacing(32)
        layout.addLayout(cards, 1)
        layout.addSpacing(24)
        layout.addWidget(panel)
        layout.addSpacing(14)

    # ---------- helpers ----------
    def _step_row(self, num: str, text: str) -> QHBoxLayout:
        badge = QLabel(num)
        badge.setObjectName("stepBadge")
        badge.setFixedSize(24, 24)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl = QLabel(text)
        lbl.setObjectName("stepText")
        row = QHBoxLayout()
        row.setSpacing(12)
        row.addWidget(badge)
        row.addWidget(lbl, 1)
        return row

    # ---------- public API ----------
    def set_api_status(self, connected: bool) -> None:
        self.pill.setText("●  API connected" if connected else "●  API not connected")
        self.pill.setProperty("state", "ok" if connected else "off")
        self.pill.style().unpolish(self.pill)
        self.pill.style().polish(self.pill)

class StatsPage(QWidget):
    def __init__(self):
        super().__init__()
        title = QLabel("Vulnerabilities Burndown")
        title.setObjectName("statsTitle")
        title.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.addWidget(title)
        layout.addStretch()


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

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_values = {}
        for name in ("Scans", "Findings", "Verified"):
            card = QFrame()
            card.setObjectName("card")
            box = QVBoxLayout(card)
            value = QLabel("0")
            value.setObjectName("cardValue")
            box.addWidget(value)
            box.addWidget(QLabel(name))
            self.card_values[name] = value
            cards.addWidget(card)

        self.table = make_table(
            ["Repository", "Model", "Mode", "Date", "Findings", "Tokens", "Duration"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(2, 100)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 115)
        self.table.setColumnWidth(5, 100)
        self.table.setColumnWidth(6, 115)
        self._records = []
        self._sort_column = None
        self._sort_order = Qt.AscendingOrder
        header = self.table.horizontalHeader()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(False)
        header.sectionClicked.connect(self._toggle_sort)
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._clear_sort)
        self.table.cellClicked.connect(self._select_record)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addLayout(cards)
        layout.addWidget(self.table, 1)

    def refresh(self, records):
        self._records = list(records)
        findings = [f for rec in self._records for f in rec.findings]
        counts = (len(self._records), len(findings),
                  sum(f.status == "Verified" for f in findings))
        for label, count in zip(self.card_values.values(), counts):
            label.setText(str(count))

        indexed_records = list(enumerate(self._records))
        if self._sort_column is not None:
            indexed_records.sort(
                key=lambda entry: self._sort_key(entry[1], self._sort_column),
                reverse=self._sort_order == Qt.DescendingOrder,
            )

        self.table.setRowCount(len(indexed_records))
        for row, (record_index, rec) in enumerate(indexed_records):
            values = [rec.repo, rec.model, rec.mode, rec.date, str(len(rec.findings)),
                      rec.tokens, rec.duration]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if col == 0:
                    item.setData(Qt.UserRole, record_index)
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()
        if self._sort_column is not None:
            self.table.horizontalHeader().setSortIndicator(
                self._sort_column, self._sort_order)

    def _toggle_sort(self, column):
        if self._sort_column != column:
            order = Qt.AscendingOrder
        elif self._sort_order == Qt.AscendingOrder:
            order = Qt.DescendingOrder
        else:
            order = Qt.AscendingOrder
        self.sort_by_column(column, order)

    def _clear_sort(self, _position=None):
        self._sort_column = None
        self.table.horizontalHeader().setSortIndicatorShown(False)
        self.refresh(self._records)

    def sort_by_column(self, column, order=Qt.AscendingOrder):
        self._sort_column = column
        self._sort_order = order
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.refresh(self._records)

    def _select_record(self, row, _column):
        item = self.table.item(row, 0)
        if item is not None:
            self.record_selected.emit(item.data(Qt.UserRole))

    @staticmethod
    def _sort_key(record, column):
        values = [record.repo, record.model, record.mode, record.date,
                  len(record.findings), record.tokens, record.duration]
        value = values[column]
        if column == 3:
            try:
                return (0, datetime.strptime(value, "%b %d, %Y"))
            except ValueError:
                return (1, value.casefold())
        if column == 4:
            return (0, value)
        if column in (5, 6):
            number = re.match(r"^\s*(\d+(?:\.\d+)?)\s*(mins|min|hrs|hr|h|secs|sec|s|[kmb])?\b",
                              value, re.IGNORECASE)
            if number:
                amount = float(number.group(1))
                unit = (number.group(2) or "").lower()
                multiplier = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000,
                              "h": 60, "hr": 60, "hrs": 60,
                              "min": 1, "mins": 1, "s": 1 / 60,
                              "sec": 1 / 60, "secs": 1 / 60}.get(unit, 1)
                return (0, amount * multiplier)
            return (1, value.casefold())
        return (0, value.casefold())


def apply_decision(finding, decision, reason, note):
    """Record a reviewer's Accept/Ignore decision on a finding. Mocked: nothing leaves the app."""
    finding.decision = decision
    finding.reason = reason
    finding.note = note.strip()
    finding.status = decision


class DecisionDialog(QDialog):
    """Mock accept/ignore form: pick a reason and add context. Nothing is changed in any repository."""

    def __init__(self, parent, finding, kind):
        super().__init__(parent)
        self.finding = finding
        self.kind = kind  # "Accept" or "Ignore"
        self.decision = "Accepted" if kind == "Accept" else "Ignored"
        self.setWindowTitle(f"{kind} fix for {finding.id}")
        self.setMinimumWidth(680)

        context = QLabel(
            f"{finding.id}  |  {finding.severity}  |  {finding.cwe or 'no CWE'}\n"
            f"{finding.title}\n{finding.location}\n\n"
            f"Proposed fix (sample): {sample_fix(finding)}")
        context.setWordWrap(True)
        self.reason = QComboBox()
        self.reason.addItems(ACCEPT_REASONS if kind == "Accept" else IGNORE_REASONS)
        self.note = QPlainTextEdit()
        self.note.setPlaceholderText("Context for the team: why are you making this decision? (optional)")
        self.note.setFixedHeight(110)
        mocked = QLabel("Mocked: nothing is changed in any repository.")
        mocked.setObjectName("muted")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(f"{kind} fix")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.addWidget(context)
        layout.addWidget(QLabel("Reason"))
        layout.addWidget(self.reason)
        layout.addWidget(QLabel("Context"))
        layout.addWidget(self.note)
        layout.addWidget(mocked)
        layout.addWidget(buttons)


class CodeViewDialog(QDialog):
    """Mock code viewer: an invented snippet around the flagged line. Not from a real repository."""

    def __init__(self, parent, finding):
        super().__init__(parent)
        _path, line = split_location(finding.location)
        self.setWindowTitle(f"{finding.id}: {finding.location}")
        self.setMinimumSize(820, 420)

        header = QLabel(f"{finding.title}\n{finding.location}")
        header.setWordWrap(True)
        link = QLabel(code_url(finding))
        link.setObjectName("muted")
        link.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.code = QPlainTextEdit()
        self.code.setReadOnly(True)
        self.code.setFont(QFont("Consolas", 11))
        rows = sample_snippet(finding)
        self.code.setPlainText(
            "\n".join(f"{'>' if n == line else ' '} {n:>4} | {text}" for n, text in rows)
            if rows else "No sample snippet for this finding.")
        note = QLabel("Sample snippet, invented for the demo. The link above is a sample and is not opened.")
        note.setObjectName("muted")
        note.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.addWidget(header)
        layout.addWidget(link)
        layout.addWidget(self.code, 1)
        layout.addWidget(note)


class ScanPage(QWidget):
    finished = pyqtSignal(object)  # emits a ScanRecord

    def __init__(self, sample_findings, sample_output):
        super().__init__()
        self.sample_findings = sample_findings
        self.sample_output = sample_output
        self._line_index = 0
        self._run_output = []
        self._rows = []  # findings in table order
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._next_line)

        # Top row: repository, model, demo, scan
        self.repo = QLineEdit()
        self.repo.setPlaceholderText("GitHub URL or local path")
        self.model_box = QComboBox()
        self.model_box.addItems(list(MODEL_IDS) + [f"{m} (not available yet)" for m in DISABLED_MODELS])
        for i in range(len(MODEL_IDS), self.model_box.count()):
            self.model_box.model().item(i).setEnabled(False)
        self.model_box.setToolTip("Model used for the scan. Greyed-out models are not available yet.")
        self.repo.setToolTip("Repository to scan. Not used in demo mode.")
        self.demo = QCheckBox("Demo")
        self.demo.setToolTip("Replay sample data. No API key, network or Claude access needed.")
        self.demo.setChecked(True)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setToolTip("Hunt: look for exploitable vulnerabilities (demo replay only).")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.start_scan)

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.repo, 1)
        top.addWidget(self.model_box)
        top.addWidget(self.demo)
        top.addWidget(self.scan_btn)

        # Findings table
        self.table = make_table(["ID", "Severity", "Finding", "Location", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 115)
        self.table.setColumnWidth(1, 105)
        self.table.setColumnWidth(3, 290)
        self.table.setColumnWidth(4, 125)
        self.table.itemSelectionChanged.connect(self._refresh_detail)
        self.tracker = SeverityTracker()
        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self.table, 1)
        body.addWidget(self.tracker)

        # Selected finding: details and actions. Fix, Accept, Ignore and View in code are
        # mocked: they work on sample data only and never touch a repository.
        self.detail = QFrame()
        self.detail.setObjectName("card")
        self.detail_heading = QLabel()
        self.detail_heading.setStyleSheet("font-weight: 600;")
        self.detail_title = QLabel()
        self.detail_title.setWordWrap(True)
        self.code_link = QPushButton()  # styled as a link in STYLE
        self.code_link.setObjectName("link")
        self.code_link.setCursor(Qt.PointingHandCursor)
        self.code_link.setToolTip("Show the flagged code (sample snippet).")
        self.code_link.clicked.connect(self._view_code)
        self.decision_label = QLabel()
        self.decision_label.setObjectName("muted")
        self.decision_label.setWordWrap(True)

        self.fix_btn = QPushButton("Fix")
        self.fix_btn.setObjectName("primary")
        self.accept_btn = QPushButton("Accept")
        self.ignore_btn = QPushButton("Ignore")
        self.verify_btn = QPushButton("Verify")
        self.report_btn = QPushButton("Report")
        self.fix_btn.setToolTip("Fix: propose a remediation for this finding (mocked, shows a sample proposal).")
        self.accept_btn.setToolTip("Accept the proposed fix, with a reason and context (mocked).")
        self.ignore_btn.setToolTip("Ignore this finding or fix, with a reason and context (mocked).")
        self.verify_btn.setToolTip("Verify: check that this finding is actually fixed (not implemented yet).")
        self.report_btn.setToolTip("Report: export this finding (not implemented yet).")
        self.fix_btn.clicked.connect(self._propose_fix)
        self.accept_btn.clicked.connect(lambda: self._decide("Accept"))
        self.ignore_btn.clicked.connect(lambda: self._decide("Ignore"))
        for btn in (self.verify_btn, self.report_btn):
            btn.clicked.connect(lambda _checked, b=btn: self._not_implemented(b.text()))

        heading_row = QHBoxLayout()
        heading_row.addWidget(self.detail_heading)
        heading_row.addStretch()
        heading_row.addWidget(self.code_link)
        actions = QHBoxLayout()
        actions.setSpacing(10)
        for btn in (self.fix_btn, self.accept_btn, self.ignore_btn):
            actions.addWidget(btn)
        actions.addStretch()
        for btn in (self.verify_btn, self.report_btn):
            actions.addWidget(btn)
        detail_box = QVBoxLayout(self.detail)
        detail_box.setSpacing(6)
        detail_box.addLayout(heading_row)
        detail_box.addWidget(self.detail_title)
        detail_box.addWidget(self.decision_label)
        detail_box.addLayout(actions)

        # Output
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addLayout(body, 2)
        layout.addWidget(self.detail)
        layout.addWidget(self.output, 1)

        self._refresh_detail()

    # Page states
    def reset(self):
        """Blank page for a new scan."""
        self.timer.stop()
        self._set_inputs_editable(True)
        self.repo.clear()
        self.demo.setChecked(True)
        self._fill_table([])
        self.output.clear()
        self._refresh_detail()

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

    # Scan with LLM Connector:
    def start_scan(self):
        selected_model = self.model_box.currentText()
        repo_target = self.repo.text().strip() or REPO_URL

        # If Demo mode is unchecked, trigger the live LLMConnector route!
        if not self.demo.isChecked():
            self.output.clear()
            self.output.appendPlainText(f"Connecting to {selected_model} for live scan on: {repo_target}...\n")
            
            try:
                # 1. Initialize your unified connector with the dropdown selection
                connector = LLMConnector(selected_model)
                
                # 2. Construct your prompt/query for the vulnerability scan
                prompt = f"Perform a security vulnerability analysis on the codebase at: {repo_target}"
                
                # 3. Generate response and display it in the output text box
                response = connector.generate_response(prompt)
                self.output.appendPlainText(response)
                
            except Exception as e:
                self.output.appendPlainText(f"Error connecting to model: {str(e)}")
            return

        # Otherwise, run your existing simulated demo replay workflow
        self._fill_table([])
        self.output.clear()
        self.scan_btn.setEnabled(False)
        self._line_index = 0
        self._run_output = self._output_for_model()
        self.timer.start(500)

    def _output_for_model(self):
        model = self.model_box.currentText()
        return [line.replace("{model_id}", MODEL_IDS.get(model, model)) for line in self.sample_output]

    def _next_line(self):
        if self._line_index < len(self._run_output):
            self.output.appendPlainText(self._run_output[self._line_index])
            self._line_index += 1
            return
        self.timer.stop()
        # Copies, so a decision on one scan never changes the sample data or other scans.
        findings = [replace(f) for f in self.sample_findings]
        self._fill_table(findings)
        self.scan_btn.setEnabled(True)
        now = datetime.now()
        record = ScanRecord(
            repo=self.repo.text().strip() or REPO_URL,
            model=self.model_box.currentText(),
            mode="Demo",
            date=f"{now:%b} {now.day}, {now.year}",
            findings=findings,
            output=list(self._run_output),
            tokens="n/a",  # a demo replay measures nothing, so show no usage figures
            duration="n/a",
        )
        self.finished.emit(record)

    def _fill_table(self, findings):
        self.tracker.update_counts(findings)
        # A severity outside SEVERITY_ORDER sorts last instead of raising.
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
                          if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER))
        self._rows = findings
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            for col, value in enumerate([f.id, f.severity, f.title, f.location, f.status]):
                self.table.setItem(row, col, QTableWidgetItem(value))
        self.table.resizeRowsToContents()
        if findings:
            self.table.selectRow(0)

    def _current_finding(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows or rows[0].row() >= len(self._rows):
            return None
        return self._rows[rows[0].row()]

    def _refresh_detail(self):
        """Show the selected finding's details and enable its actions."""
        finding = self._current_finding()
        for btn in (self.fix_btn, self.accept_btn, self.ignore_btn, self.verify_btn, self.report_btn):
            btn.setEnabled(finding is not None)
        if finding is None:
            self.detail_heading.setText("No finding selected")
            self.detail_title.setText("Select a finding to see its details and actions.")
            self.code_link.setText("")
            self.code_link.hide()
            self.decision_label.hide()
            return
        self.detail_heading.setText(
            f"{finding.id}  |  {finding.severity}  |  {finding.cwe or 'no CWE'}  |  {finding.status}")
        self.detail_title.setText(finding.title)
        self.code_link.setText(f"View in code: {finding.location}")
        self.code_link.show()
        if finding.decision:
            text = f"{finding.decision}: {finding.reason}"
            if finding.note:
                text += f". Context: {finding.note}"
            self.decision_label.setText(text)
            self.decision_label.show()
        else:
            self.decision_label.hide()

    def _refresh_status(self):
        """Put the selected finding's status back into its table row, then refresh the details."""
        rows = self.table.selectionModel().selectedRows()
        finding = self._current_finding()
        if finding is not None:
            self.table.item(rows[0].row(), 4).setText(finding.status)
        self._refresh_detail()

    # Mocked actions on the selected finding
    def _propose_fix(self):
        finding = self._current_finding()
        if finding is None:
            return
        if not finding.decision:
            finding.status = "Fix proposed"
        self._refresh_status()
        QMessageBox.information(
            self, "VulnHunter",
            f"Sample fix proposal for {finding.id}:\n\n{sample_fix(finding)}\n\n"
            "Mocked: a real Fix would create a branch, write tests and open a pull request. "
            "Nothing was changed.")

    def _decide(self, kind):
        finding = self._current_finding()
        if finding is None:
            return
        dialog = DecisionDialog(self, finding, kind)
        if dialog.exec_() == QDialog.Accepted:
            apply_decision(finding, dialog.decision, dialog.reason.currentText(),
                           dialog.note.toPlainText())
            self._refresh_status()

    def _view_code(self):
        finding = self._current_finding()
        if finding is not None:
            CodeViewDialog(self, finding).exec_()

    def _not_implemented(self, name):
        QMessageBox.information(self, "VulnHunter", f"{name} is not implemented yet.")


class MainWindow(QMainWindow):
    HOME, HISTORY, SCAN, STATS, CONNECT = 0, 1, 2, 3, 4
    MIN_ZOOM = 0.7
    MAX_ZOOM = 2.0
    DEFAULT_ZOOM = 1.0
    ZOOM_STEP = 0.1

    def __init__(self):
        super().__init__()
        self._zoom = self.DEFAULT_ZOOM
        self.setWindowTitle("VulnHunter")
        self.setMinimumSize(*MIN_WINDOW_SIZE)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(*default_window_size(screen.width(), screen.height()))
        # Newest first; held in memory only. Copies, so decisions never change the sample data.
        self.history = [replace(r, findings=[replace(f) for f in r.findings]) for r in SEED_HISTORY]

        self.home_page = HomePage()
        self.history_page = HistoryPage()
        self.scan_page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
        self.stats_page = StatsPage()
        self.connector_page = ApiConnectorPage()
        self.connector_page.connected.connect(self.on_llm_connected)
        self.connector_page.disconnected.connect(self.on_llm_disconnected)
        self.connected_provider = None
        self.stack = QStackedWidget()
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.history_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.stats_page)
        self.stack.addWidget(self.connector_page)
        self._page_history = [self.HOME]
        self._page_history_position = 0
        self.home_page.stats_requested.connect(self.show_stats)
        self.home_page.connector_requested.connect(self.show_connector)

        # Shared header: navigation controls and a centered home button.
        header = QFrame()
        header.setObjectName("header")
        header.setFixedHeight(72)
        self.back_button = QPushButton("‹")
        self.back_button.setObjectName("backNavigation")
        self.back_button.setToolTip("Go to the previous page (Ctrl/Cmd+Left)")
        self.back_button.clicked.connect(self.go_back)
        self.forward_button = QPushButton("›")
        self.forward_button.setObjectName("forwardNavigation")
        self.forward_button.setToolTip("Go to the next page (Ctrl/Cmd+Right)")
        self.forward_button.clicked.connect(self.go_forward)
        navigation = QWidget()
        navigation_layout = QHBoxLayout(navigation)
        navigation_layout.setContentsMargins(0, 0, 0, 0)
        navigation_layout.setSpacing(8)
        navigation_layout.addWidget(self.back_button)
        navigation_layout.addWidget(self.forward_button)

        home = QPushButton("VulnHunter")
        home.setObjectName("home")
        home.setMinimumSize(260, 48)
        home.setCursor(Qt.PointingHandCursor)
        home.clicked.connect(self.show_home)
        self.home_button = home
        right_spacer = QWidget()
        right_spacer.setFixedWidth(navigation.sizeHint().width())
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)
        header_layout.addWidget(navigation)
        header_layout.addStretch()
        header_layout.addWidget(home)
        header_layout.addStretch()
        header_layout.addWidget(right_spacer)
        self._update_navigation_buttons()

        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.home_page.dashboard_requested.connect(self.show_history)
        self.history_page.new_scan.connect(self.new_scan)
        self.history_page.record_selected.connect(self.open_record)
        self.scan_page.finished.connect(self.add_record)
        self.history_page.refresh(self.history)
        self._apply_zoom(self.DEFAULT_ZOOM)

    def show_home(self):
        self._navigate_to(self.HOME)

    def show_stats(self):
        self._navigate_to(self.STATS)

    def show_connector(self):
        self._navigate_to(self.CONNECT)

    def on_llm_connected(self, provider_key, provider_label):
        self.connected_provider = (provider_key, provider_label)
        print(f"Successfully connected to {provider_label} ({provider_key})")

    def on_llm_disconnected(self):
        self.connected_provider = None
        print("LLM disconnected.")

    def show_history(self):
        self._navigate_to(self.HISTORY)

    def new_scan(self):
        self.scan_page.reset()
        self._navigate_to(self.SCAN)

    def open_record(self, row):
        self.scan_page.show_record(self.history[row])
        self._navigate_to(self.SCAN)

    def _navigate_to(self, page_index):
        if self.stack.currentIndex() == page_index:
            return
        del self._page_history[self._page_history_position + 1:]
        self._page_history.append(page_index)
        self._page_history_position += 1
        self.stack.setCurrentIndex(page_index)
        self._update_navigation_buttons()

    def go_back(self):
        if self._page_history_position == 0:
            return
        self._page_history_position -= 1
        self.stack.setCurrentIndex(self._page_history[self._page_history_position])
        self._update_navigation_buttons()

    def go_forward(self):
        if self._page_history_position >= len(self._page_history) - 1:
            return
        self._page_history_position += 1
        self.stack.setCurrentIndex(self._page_history[self._page_history_position])
        self._update_navigation_buttons()

    def _update_navigation_buttons(self):
        self.back_button.setEnabled(self._page_history_position > 0)
        self.forward_button.setEnabled(
            self._page_history_position < len(self._page_history) - 1)

    def add_record(self, record):
        self.history.insert(0, record)
        self.history_page.refresh(self.history)

    def _clamp_zoom(self, zoom):
        bounded_zoom = max(self.MIN_ZOOM, min(self.MAX_ZOOM, zoom))
        return round(bounded_zoom, 2)

    def _apply_zoom(self, target_zoom):
        self._zoom = self._clamp_zoom(target_zoom)
        stylesheet = zoom_stylesheet(self._zoom)
        if self.styleSheet() != stylesheet:
            self.setStyleSheet(stylesheet)
        self.home_page.setStyleSheet(scaled_stylesheet(HOME_QSS, self._zoom))
        for table in self.findChildren(QTableWidget):
            table.resizeRowsToContents()

    def zoom_in(self):
        target_zoom = self._clamp_zoom(self._zoom + self.ZOOM_STEP)
        if target_zoom > self._zoom:
            self._apply_zoom(target_zoom)

    def zoom_out(self):
        target_zoom = self._clamp_zoom(self._zoom - self.ZOOM_STEP)
        if target_zoom < self._zoom:
            self._apply_zoom(target_zoom)

    def reset_zoom(self):
        self._apply_zoom(self.DEFAULT_ZOOM)

    def _handle_zoom_shortcut(self, event):
        modifiers = event.modifiers()
        is_zoom_modifier = bool(modifiers & (Qt.ControlModifier | Qt.MetaModifier))
        if not is_zoom_modifier:
            return False

        if event.key() in (Qt.Key_Plus, Qt.Key_Equal):
            self.zoom_in()
            event.accept()
            return True
        if event.key() in (Qt.Key_Minus, Qt.Key_Underscore):
            self.zoom_out()
            event.accept()
            return True
        if event.key() == Qt.Key_0:
            self.reset_zoom()
            event.accept()
            return True
        return False

    def _handle_navigation_shortcut(self, event):
        modifiers = event.modifiers()
        if not modifiers & (Qt.ControlModifier | Qt.MetaModifier):
            return False
        if modifiers & Qt.ShiftModifier:
            return False
        if event.key() == Qt.Key_Left:
            self.go_back()
        elif event.key() == Qt.Key_Right:
            self.go_forward()
        else:
            return False
        event.accept()
        return True

    def eventFilter(self, obj, event):
        if event.type() == QEvent.KeyPress and self._handle_navigation_shortcut(event):
            return True
        if event.type() == QEvent.KeyPress and self._handle_zoom_shortcut(event):
            return True
        return super().eventFilter(obj, event)

    def keyPressEvent(self, event):
        if self._handle_navigation_shortcut(event):
            return
        if self._handle_zoom_shortcut(event):
            return
        super().keyPressEvent(event)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
