import math
import random
import re
import sys
from dataclasses import replace
from datetime import datetime
from pathlib import Path

# main_gui.py is in VulnHunter/gui/, so the repo root is one level up
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import QEvent, QPoint, QPointF, QRectF, QSettings, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QConicalGradient, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QStackedWidget, QStyle, QStyledItemDelegate,
    QStyleOptionViewItem, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QSizePolicy,
)

from gui.data.mock_data import (
    ACCEPT_REASONS, ALL_REPOS, BURNDOWN_BY_REPO, DISABLED_MODELS, HUNT_PHASE, IGNORE_REASONS,
    MODEL_IDS, REPO_URL, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SCAN_PHASES, SCAN_PHRASES, SEED_HISTORY,
    SEVERITY_ORDER, ScanRecord, burndown_series, burndown_totals, code_url, phase_of_line,
    result_level, sample_fix, sample_snippet, severity_summary, split_location,
)
from llm_connector.conn_all_llm import LLMConnector
from gui.api_conn_page import ApiConnectorPage

STYLE = """
QWidget {
    color: #E6EEF8; font-size: 18px;
    font-family: "Segoe UI Variable Text", "Segoe UI", "SF Pro Text", "Inter", "Helvetica Neue", Arial, sans-serif;
}
QMainWindow, QWidget#root { background: #0A1424; }
QDialog, QMessageBox { background: #0F1C31; }
QToolTip { background: #13233C; color: #E6EEF8; border: 1px solid #223A5A; padding: 6px 8px; }
QFrame#header { background: #0A1424; border: 0; border-bottom: 1px solid #16273F; }
QFrame#card { background: #0F1C31; border: 1px solid #1B2F4B; border-radius: 14px; }
QFrame#card QLabel { background: transparent; }
QFrame#popupCard { background: #0F1C31; border: 1px solid #2A4468; border-radius: 18px; }
QFrame#popupCard QLabel { background: transparent; }
QLabel#severityHeading { font-size: 16px; font-weight: 600; color: #8CA3C0; }
QLabel#severityHeadline { font-size: 16px; font-weight: 600; }
QLabel#severityDetail { font-size: 16px; }
QLabel#statsTitle { font-size: 28px; font-weight: 600; }
QLabel#cardValue { font-size: 26px; font-weight: 600; }
QPushButton#home {
    background: transparent; border: 0; color: #E6EEF8; font-size: 28px;
    font-weight: 700; padding: 0 12px;
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
QLabel#title { font-size: 28px; font-weight: 600; }
QLabel#muted { color: #8CA3C0; }
QLabel#statusPill {
    font-size: 14px; font-weight: 600; padding: 4px 12px; border-radius: 13px;
    border: 1px solid #223A5A; background: #0D2646; color: #9FB3CC;
}
QLabel#statusPill[state="off"] { color: #F5C451; border-color: #6B5A1F; background: #2A2410; }
QLabel#statusPill[state="ok"] { color: #4ADE80; border-color: #1F5A38; background: #0F2A1C; }
QLabel#statusPill[state="error"] { color: #F87171; border-color: #6B2A2A; background: #2A1010; }
QLabel#statusPill[hover="true"] { border-color: #E6EEF8; }
QLabel#sampleTag {
    font-size: 13px; color: #9FB3CC; border: 1px solid #223A5A; border-radius: 11px;
    padding: 2px 10px; background: transparent;
}
QPushButton#iconButton {
    background: transparent; border: 0; color: #9FB3CC; font-size: 26px; padding: 0;
    min-width: 36px; max-width: 36px;
}
QPushButton#iconButton:hover { color: #38BDF8; background: transparent; }
QLabel#popupTitle { font-size: 22px; font-weight: 600; }
QLabel#phrase { font-size: 22px; font-weight: 500; }
QPushButton#link {
    background: transparent; border: 0; padding: 0; color: #38BDF8; text-decoration: underline;
}
QPushButton#link:hover { color: #7DD3FC; background: transparent; }
QCheckBox { background: transparent; spacing: 8px; }
QLineEdit, QComboBox {
    background: #0F1C31; border: 1px solid #223A5A; border-radius: 10px; padding: 10px 14px;
}
QLineEdit:focus, QComboBox:focus { border: 1px solid #38BDF8; }
QComboBox QAbstractItemView {
    background: #0F1C31; color: #E6EEF8; selection-background-color: #173553;
    selection-color: #E6EEF8; border: 1px solid #223A5A; outline: 0;
}
QPushButton {
    background: #13233C; border: 1px solid #223A5A; border-radius: 10px; padding: 10px 20px;
}
QPushButton:hover { background: #19304F; }
QPushButton:disabled { color: #6B7F99; background: #0C1829; border-color: #16273F; }
QPushButton#primary { background: #38BDF8; color: #05101F; border: 0; font-weight: 600; }
QPushButton#primary:hover { background: #7DD3FC; }
QPushButton#primary:disabled { background: #1E3A5C; color: #6B7F99; }
QTableWidget {
    background: #0F1C31; border: 1px solid #1B2F4B; border-radius: 14px;
    gridline-color: transparent; selection-background-color: #173553;
    selection-color: #E6EEF8; outline: 0;
}
QTableWidget::item { padding: 8px 12px; border-bottom: 1px solid #15263F; }
QTableWidget::item:selected { background: #173553; color: #E6EEF8; }
QHeaderView { background: #0F1C31; border: 0; }
QHeaderView::section {
    background: transparent; color: #8CA3C0; border: 0; border-bottom: 1px solid #1B2F4B;
    padding: 12px 14px; font-weight: 600; font-size: 16px;
}
QTableCornerButton::section { background: transparent; border: 0; }
QPlainTextEdit {
    background: #08111F; border: 1px solid #1B2F4B; border-radius: 12px; color: #D5E1F2;
    padding: 8px 10px; font-size: 15px;
    font-family: "Cascadia Mono", "Cascadia Code", Consolas, monospace;
}
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #223A5A; border-radius: 4px; min-height: 28px; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: #223A5A; border-radius: 4px; min-width: 28px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
"""


MIN_WINDOW_SIZE = (1300, 700)
HOME_BUTTON_PX = 28  # the VulnHunter logo button in the header; keeps its size when zooming

# Severity colours: (row background, text). Shared by the findings list, the tracker and the result card.
SEVERITY_COLORS = {
    "High+": ("#4A1220", "#FF9AA5"),  # dark red
    "High": ("#5E1F24", "#FF8080"),  # red
    "Medium": ("#5A3A14", "#FFB35C"),  # orange
    "Low": ("#54481A", "#FFE08A"),  # yellow
    "Informational": ("#1C2A44", "#B7C6DD"),  # blue-grey
}
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
        f"QPushButton#home {{ font-size: {HOME_BUTTON_PX}px; }}\n"
        f"QTableWidget {{ font-size: {round(18 * scale)}px; }}\n"
        f"QHeaderView::section {{ font-size: {round(18 * scale)}px; }}"
    )


def make_table(headers):
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setWordWrap(True)
    table.setShowGrid(False)
    table.horizontalHeader().setHighlightSections(False)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    return table


class SeverityRowDelegate(QStyledItemDelegate):
    """Paints each row in its severity colour. A selected row keeps its colour and gets a light outline."""

    def paint(self, painter, option, index):
        selected = bool(option.state & QStyle.State_Selected)
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.state &= ~QStyle.State_Selected  # the selection colour would hide the severity colour
        background = index.data(Qt.BackgroundRole)
        if background is not None:
            painter.fillRect(option.rect, background)
        super().paint(painter, opt, index)
        if selected:
            painter.save()
            painter.setPen(QPen(QColor("#E6EEF8"), 2))
            r = option.rect
            painter.drawLine(r.left(), r.top() + 1, r.right(), r.top() + 1)
            painter.drawLine(r.left(), r.bottom() - 1, r.right(), r.bottom() - 1)
            if index.column() == 0:
                painter.drawLine(r.left() + 1, r.top(), r.left() + 1, r.bottom())
            if index.column() == index.model().columnCount() - 1:
                painter.drawLine(r.right() - 1, r.top(), r.right() - 1, r.bottom())
            painter.restore()


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
            colours = SEVERITY_COLORS.get(name)
            if colours:
                count.setStyleSheet(f"color: {colours[1]};")
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

#homeHeading { font-size: 44px; font-weight: 700; color: #f1f6fd; }
#homeSub     { font-size: 18px; color: #9fb4d0; }
#homeNewScan {
    background: #38bdf8; color: #05101f; border: 0; border-radius: 10px;
    font-size: 20px; font-weight: 700; padding: 14px 48px;
}
#homeNewScan:hover   { background: #7dd3fc; }
#homeNewScan:pressed { background: #0ea5e9; }

/* module cards */
#moduleCard {
    background: #0f1c31; border: 1px solid #1b2f4b;
    border-radius: 18px; text-align: left;
}
#moduleCard:hover   { background: #13253f; border: 1px solid #2c4a73; }
#moduleCard:pressed { background: #0c182a; }
#homePage QLabel#cardIcon {
    font-family: "Segoe UI Symbol", "Segoe UI";
    font-size: 24px; color: #38bdf8;
    background: rgba(56,189,248,0.12); border-radius: 12px;
}
#cardTitle { font-size: 24px; font-weight: 700; color: #f1f6fd; }
#cardDesc  { font-size: 16px; color: #9fb4d0; }
#cardGo    { font-size: 16px; font-weight: 700; color: #38bdf8; }

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
    history_requested = pyqtSignal()
    stats_requested = pyqtSignal()
    new_scan_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("homePage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(HOME_QSS)

        heading = QLabel("Welcome back, dev")
        heading.setObjectName("homeHeading")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub = QLabel("Review findings, track stats, or start a scan.")
        sub.setObjectName("homeSub")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.new_scan_btn = QPushButton("New Scan")
        self.new_scan_btn.setObjectName("homeNewScan")
        self.new_scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.new_scan_btn.setToolTip("Start a new scan of a repository.")
        self.new_scan_btn.clicked.connect(self.new_scan_requested.emit)

        cards = QHBoxLayout()
        cards.setSpacing(20)
        cards.addStretch(1)
        for icon, title, desc, signal in [
            ("▦", "Scan History", "Past scans and their findings.", self.history_requested),
            ("◔", "Stats", "Burndown across all repos.", self.stats_requested),
        ]:
            card = ModuleCard(icon, title, desc)
            card.clicked.connect(signal.emit)
            cards.addWidget(card, 3)
        cards.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 36, 48, 36)
        layout.setSpacing(0)
        layout.addStretch(1)
        layout.addWidget(heading)
        layout.addSpacing(8)
        layout.addWidget(sub)
        layout.addSpacing(26)
        layout.addWidget(self.new_scan_btn, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addSpacing(30)
        layout.addLayout(cards)
        layout.addStretch(2)


class BurndownChart(QWidget):
    """Open findings over time, drawn with QPainter (no chart library needed)."""
    LINE, IDEAL, GRID, TEXT = "#38BDF8", "#7F93AD", "#243B5C", "#E6EEF8"

    def __init__(self, points=(), compact=False):
        super().__init__()
        self.compact = compact
        self.points = list(points)  # [(label, open_count), ...]
        self.setMinimumHeight(110 if compact else 300)

    def set_points(self, points):
        self.points = list(points)
        self.update()

    def paintEvent(self, _event):
        if not self.points:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setFont(QFont("Segoe UI", 7 if self.compact else 10))
        left, right, top, bottom = (24, 8, 12, 20) if self.compact else (56, 28, 72, 48)
        plot = QRectF(left, top, max(self.width() - left - right, 1),
                      max(self.height() - top - bottom, 1))
        highest = max(max(v for _, v in self.points), 1)
        step = max(1, -(-highest // (3 if self.compact else 6)))
        peak = step * -(-highest // step)  # axis top: next multiple of the step, so it gets a gridline

        def point(i, value):
            n = len(self.points)
            x = plot.left() + (plot.width() * i / (n - 1) if n > 1 else plot.width() / 2)
            return QPointF(x, plot.bottom() - plot.height() * value / peak)

        for tick in range(0, peak + 1, step):
            y = plot.bottom() - plot.height() * tick / peak
            p.setPen(QPen(QColor(self.GRID), 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(QColor(self.TEXT))
            p.drawText(QRectF(0, y - 10, left - 6, 20), Qt.AlignRight | Qt.AlignVCenter, str(tick))

        last = len(self.points) - 1
        p.setPen(QPen(QColor(self.IDEAL), 1.5, Qt.DashLine))
        p.drawLine(point(0, self.points[0][1]), point(last, 0))
        p.setPen(QPen(QColor(self.LINE), 2 if self.compact else 3))
        for i in range(last):
            p.drawLine(point(i, self.points[i][1]), point(i + 1, self.points[i + 1][1]))
        p.setBrush(QColor(self.LINE))
        radius = 3 if self.compact else 5
        for i, (label, value) in enumerate(self.points):
            pos = point(i, value)
            p.setPen(QPen(QColor(self.LINE), 1))
            p.drawEllipse(pos, radius, radius)
            p.setPen(QColor(self.TEXT))
            axis_label = label.replace("Week ", "W") if self.compact else label
            p.drawText(QRectF(pos.x() - 30, plot.bottom() + 4, 60, 18), Qt.AlignCenter, axis_label)
            if not self.compact:
                p.drawText(QRectF(pos.x() - 20, pos.y() - 30, 40, 20), Qt.AlignCenter, str(value))

        if not self.compact:
            p.setPen(QPen(QColor(self.LINE), 3))
            p.drawLine(QPointF(left, 16), QPointF(left + 28, 16))
            p.setPen(QColor(self.TEXT))
            p.drawText(QRectF(left + 36, 4, 160, 24), Qt.AlignLeft | Qt.AlignVCenter, "Open findings")
            p.setPen(QPen(QColor(self.IDEAL), 2, Qt.DashLine))
            p.drawLine(QPointF(left + 200, 16), QPointF(left + 228, 16))
            p.setPen(QColor(self.TEXT))
            p.drawText(QRectF(left + 236, 4, 200, 24), Qt.AlignLeft | Qt.AlignVCenter, "Ideal burndown")


class StatsPage(QWidget):
    """Burndown across all sample repos, with a repo filter. Sample data only."""

    def __init__(self):
        super().__init__()
        title = QLabel("Vulnerabilities Burndown")
        title.setObjectName("statsTitle")
        self.repo_box = QComboBox()
        self.repo_box.addItem(ALL_REPOS)
        self.repo_box.addItems(list(BURNDOWN_BY_REPO))
        self.repo_box.setToolTip("Show the burndown for all repos or for one.")
        self.repo_box.currentIndexChanged.connect(self._update)

        top = QHBoxLayout()
        top.addWidget(title)
        top.addStretch()
        top.addWidget(self.repo_box)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_values = {}
        for name in ("Open", "Closed", "Total"):
            card = QFrame()
            card.setObjectName("card")
            box = QVBoxLayout(card)
            value = QLabel("0")
            value.setObjectName("cardValue")
            box.addWidget(value)
            box.addWidget(QLabel(name))
            self.card_values[name] = value
            cards.addWidget(card)

        self.chart = BurndownChart()
        note = QLabel("Solid: open findings. Dashed: ideal burndown. "
                      "Sample data, not real scan results.")
        note.setObjectName("muted")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addLayout(cards)
        layout.addWidget(self.chart, 1)
        layout.addWidget(note)
        self._update()

    def _update(self, *_args):
        series = burndown_series(self.repo_box.currentText())
        self.chart.set_points(series)
        for name, value in zip(("Open", "Closed", "Total"), burndown_totals(series)):
            self.card_values[name].setText(str(value))


ALL_MODELS = "All models"


class HistoryPage(QWidget):
    new_scan = pyqtSignal()
    record_selected = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        title = QLabel("Scan History")
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

        self.repo_filter = QComboBox()
        self.repo_filter.addItem(ALL_REPOS)
        self.repo_filter.setToolTip("Show scans for one repository.")
        self.model_filter = QComboBox()
        self.model_filter.addItem(ALL_MODELS)
        self.model_filter.setToolTip("Show scans run with one model.")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search scans")
        self.repo_filter.currentIndexChanged.connect(self._render)
        self.model_filter.currentIndexChanged.connect(self._render)
        self.search.textChanged.connect(self._render)
        filters = QHBoxLayout()
        filters.setSpacing(10)
        filters.addWidget(self.repo_filter)
        filters.addWidget(self.model_filter)
        filters.addWidget(self.search, 1)

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
        layout.addLayout(filters)
        layout.addWidget(self.table, 1)

    def refresh(self, records):
        self._records = list(records)
        self._sync_filters()
        self._render()

    def _sync_filters(self):
        """Refill the repo and model filters from the records, keeping the current choice."""
        for box, first, values in (
                (self.repo_filter, ALL_REPOS, [r.repo for r in self._records]),
                (self.model_filter, ALL_MODELS, [r.model for r in self._records])):
            current = box.currentText()
            box.blockSignals(True)
            box.clear()
            box.addItem(first)
            box.addItems(list(dict.fromkeys(values)))
            index = box.findText(current)
            box.setCurrentIndex(index if index >= 0 else 0)
            box.blockSignals(False)

    def _visible_records(self):
        """[(index in self._records, record), ...] that pass the filters."""
        repo = self.repo_filter.currentText()
        model = self.model_filter.currentText()
        text = self.search.text().strip().casefold()
        visible = []
        for index, rec in enumerate(self._records):
            if repo != ALL_REPOS and rec.repo != repo:
                continue
            if model != ALL_MODELS and rec.model != model:
                continue
            if text and text not in " ".join((rec.repo, rec.model, rec.mode, rec.date)).casefold():
                continue
            visible.append((index, rec))
        return visible

    def _render(self, *_args):
        indexed_records = self._visible_records()
        findings = [f for _index, rec in indexed_records for f in rec.findings]
        counts = (len(indexed_records), len(findings),
                  sum(f.status == "Verified" for f in findings))
        for label, count in zip(self.card_values.values(), counts):
            label.setText(str(count))

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
        self._render()

    def sort_by_column(self, column, order=Qt.AscendingOrder):
        self._sort_column = column
        self._sort_order = order
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self._render()

    def _select_record(self, row, _column):
        item = self.table.item(row, 0)
        if item is not None:
            self.record_selected.emit(item.data(Qt.UserRole))

    def showEvent(self, event):
        super().showEvent(event)
        self.table.resizeRowsToContents()  # column widths are final now, so wrapped rows get the right height

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.table.resizeRowsToContents()

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


REMINDER_KEY = "gettingStarted/hidden"


def reminder_hidden(settings):
    """True once the user ticked 'Don't show this again' on the Getting started reminder."""
    return settings.value(REMINDER_KEY, False, type=bool)


def set_reminder_hidden(settings, hidden):
    settings.setValue(REMINDER_KEY, bool(hidden))
    settings.sync()


class StatusPill(QLabel):
    """API status in the header: pulsing yellow until connected, green once it is, red if rejected.
    Clicking it opens the API settings."""
    clicked = pyqtSignal()
    TOOLTIPS = {
        "off": "Click to enter your API key",
        "ok": "Click to configure API key",
        "error": "Click to configure API key",
    }
    STATES = {
        # state: (label, dot colour, dimmed dot colour while pulsing)
        "off": ("API not connected", "#F5C451", "#6B5A1F"),
        "ok": ("Connected", "#4ADE80", None),
        "error": ("Key rejected", "#F87171", None),
    }

    def __init__(self):
        super().__init__()
        self.setObjectName("statusPill")
        self.setTextFormat(Qt.RichText)
        self.setCursor(Qt.PointingHandCursor)
        self.setProperty("hover", False)
        self._bright = True
        self._timer = QTimer(self)
        self._timer.setInterval(700)
        self._timer.timeout.connect(self._pulse)
        self._state = "off"
        self.set_state("off")

    def state(self):
        return self._state

    def label_text(self):
        return self.STATES[self._state][0]

    def is_pulsing(self):
        return self._timer.isActive()

    def set_state(self, state, detail=""):
        """Show a state. `detail` (for example 'Connected to DeepSeek') leads the hover tooltip."""
        self._state = state
        self.setToolTip(f"{detail}. {self.TOOLTIPS[state]}" if detail else self.TOOLTIPS[state])
        self.setProperty("state", state)
        self._repolish()
        self._bright = True
        self._render()
        if self.STATES[state][2]:
            self._timer.start()
        else:
            self._timer.stop()

    def _repolish(self):
        self.style().unpolish(self)
        self.style().polish(self)

    def enterEvent(self, event):
        self.setProperty("hover", True)
        self._repolish()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setProperty("hover", False)
        self._repolish()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.rect().contains(event.pos()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def _pulse(self):
        self._bright = not self._bright
        self._render()

    def _render(self):
        label, bright, dim = self.STATES[self._state]
        colour = bright if self._bright or not dim else dim
        self.setText(f'<span style="color:{colour}">●</span>&nbsp;&nbsp;{label}')


class RadarSpinner(QWidget):
    """A green sonar scope: a sweeping arm with a fading trail, and blips that light up as it passes."""
    SWEEP_STEP = 3.0  # degrees per frame at 25ms, so one turn takes 3 seconds
    GREEN, BLIP, RING, TICK, FACE = "#4ADE80", "#86EFAC", "#1F5A45", "#2E7D5B", "#08181A"
    # (x, y as fractions of the radius, blip radius at the 76px base radius)
    BLIPS = ((0.576, -0.508, 5), (0.370, 0.318, 4), (-0.518, -0.091, 5))

    def __init__(self, size=96):
        super().__init__()
        self.setFixedSize(size, size)
        self._angle = 40.0  # degrees, counter-clockwise from 3 o'clock
        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._tick)

    def is_spinning(self):
        return self._timer.isActive()

    def showEvent(self, event):
        self._timer.start()
        super().showEvent(event)

    def hideEvent(self, event):
        self._timer.stop()
        super().hideEvent(event)

    def _tick(self):
        self._angle = (self._angle - self.SWEEP_STEP) % 360.0  # clockwise
        self.update()

    @staticmethod
    def blip_alpha(behind_degrees):
        """Opacity of a blip that the sweep passed `behind_degrees` ago: full, fading to dim."""
        fraction = (behind_degrees % 360) / 360
        if fraction >= 0.55:
            return int(255 * 0.12)
        return int(255 * (1 - (fraction / 0.55) * 0.88))

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        radius = min(self.width(), self.height()) / 2 - 3
        u = radius / 76.0  # everything below is drawn for a 76px radius
        centre = QPointF(self.width() / 2, self.height() / 2)
        disc = QPainterPath()
        disc.addEllipse(centre, radius, radius)
        p.fillPath(disc, QColor(self.FACE))

        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor(self.RING), max(1.5, 1.5 * u)))
        for fraction in (0.737, 0.474, 0.21):
            p.drawEllipse(centre, radius * fraction, radius * fraction)
        p.setPen(QPen(QColor(self.RING), max(2.0, 2.5 * u)))
        p.drawEllipse(centre, radius, radius)

        # Tick marks around the rim: the four compass points and the diagonals.
        p.setPen(QPen(QColor(self.TICK), max(1.5, 2 * u), Qt.SolidLine, Qt.RoundCap))
        for degrees in range(0, 360, 45):
            direction = math.radians(degrees)
            length = (8 if degrees % 90 == 0 else 5) * u
            outer = radius - 4 * u
            p.drawLine(
                QPointF(centre.x() + outer * math.cos(direction), centre.y() - outer * math.sin(direction)),
                QPointF(centre.x() + (outer - length) * math.cos(direction),
                        centre.y() - (outer - length) * math.sin(direction)))

        # The fading trail behind the sweep arm.
        p.save()
        p.setClipPath(disc)
        trail = QConicalGradient(centre, self._angle)
        trail.setColorAt(0.0, QColor(74, 222, 128, 95))
        trail.setColorAt(0.22, QColor(74, 222, 128, 0))
        trail.setColorAt(1.0, QColor(74, 222, 128, 0))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(trail))
        p.drawEllipse(centre, radius, radius)
        p.restore()

        # Blips light up as the arm passes over them, then fade until the next pass.
        for dx, dy, size in self.BLIPS:
            blip_angle = math.degrees(math.atan2(-dy, dx)) % 360
            behind = (blip_angle - self._angle) % 360
            colour = QColor(self.BLIP)
            colour.setAlpha(self.blip_alpha(behind))
            p.setPen(Qt.NoPen)
            p.setBrush(colour)
            p.drawEllipse(QPointF(centre.x() + dx * radius, centre.y() + dy * radius), size * u, size * u)

        angle = math.radians(self._angle)
        tip = QPointF(centre.x() + radius * math.cos(angle), centre.y() - radius * math.sin(angle))
        p.setPen(QPen(QColor(self.GREEN), max(2.0, 3 * u), Qt.SolidLine, Qt.RoundCap))
        p.drawLine(centre, tip)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(self.GREEN))
        p.drawEllipse(centre, 4 * u, 4 * u)


class DimOverlay(QWidget):
    """Darkens the window behind a modal popup and swallows clicks."""

    def __init__(self, window):
        super().__init__(window)
        self._window = window
        window.installEventFilter(self)
        self.setGeometry(window.rect())
        self.show()
        self.raise_()

    def eventFilter(self, obj, event):
        if obj is self._window and event.type() == QEvent.Resize:
            self.setGeometry(self._window.rect())
            self.raise_()
        return False

    def paintEvent(self, _event):
        QPainter(self).fillRect(self.rect(), QColor(0, 0, 0, 150))

    def dismiss(self):
        self._window.removeEventFilter(self)
        self.hide()
        self.deleteLater()


class FloatingCard(QDialog):
    """A frameless rounded card over the main window: at the bottom centre by default, or the middle."""
    MARGIN = 28
    CENTERED = False

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setStyleSheet("QDialog { background: transparent; }")
        self.card = QFrame(self)
        self.card.setObjectName("popupCard")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.card)

    def showEvent(self, event):
        super().showEvent(event)
        self.adjustSize()
        self.place()

    def place(self):
        parent = self.parentWidget()
        anchor = parent.window() if parent is not None else None
        if anchor is None:
            return
        origin = anchor.mapToGlobal(QPoint(0, 0))
        x = origin.x() + (anchor.width() - self.width()) // 2
        if self.CENTERED:
            y = origin.y() + (anchor.height() - self.height()) // 2
        else:
            y = origin.y() + anchor.height() - self.height() - self.MARGIN
        self.move(x, y)


class PhraseRotator:
    """Hands out the next loading phrase for a scan phase, cycling through that phase's list.

    The hunt phase is shuffled; the others keep their order so a scan starts with 'Detecting...'
    and ends with 'Sorting by severity...'.
    """

    def __init__(self, rng=None):
        self._rng = rng or random.Random()
        self._queues = {}

    def next(self, phase):
        queue = self._queues.get(phase)
        if not queue:
            queue = list(SCAN_PHRASES[phase])
            if phase == HUNT_PHASE:
                self._rng.shuffle(queue)
            self._queues[phase] = queue
        return queue.pop(0)


class GettingStartedDialog(QDialog):
    """A closable reminder of the first steps, shown on launch until the user opts out."""
    STEPS = ["Connect your API: click the status at the top right",
             "Start a New Scan, or open Scan History",
             "Review findings, then Fix, Accept or Ignore"]

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Getting started")
        self.setMinimumWidth(480)
        title = QLabel("Getting started")
        title.setObjectName("popupTitle")

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.addWidget(title)
        for number, text in enumerate(self.STEPS, 1):
            badge = QLabel(str(number))
            badge.setFixedSize(26, 26)
            badge.setAlignment(Qt.AlignCenter)
            badge.setStyleSheet("background: #38BDF8; color: #05101F; border-radius: 13px; font-weight: 600;")
            row = QHBoxLayout()
            row.setSpacing(12)
            row.addWidget(badge)
            row.addWidget(QLabel(text), 1)
            layout.addLayout(row)

        self.dont_show = QCheckBox("Don't show this again")
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        footer = QHBoxLayout()
        footer.addWidget(self.dont_show)
        footer.addStretch()
        footer.addWidget(self.close_btn)
        layout.addSpacing(6)
        layout.addLayout(footer)


class ApiSettingsDialog(QDialog):
    """The API connector, opened from the gear icon in the header."""

    def __init__(self, parent, connector_page):
        super().__init__(parent)
        self.setWindowTitle("API settings")
        self.setMinimumWidth(640)
        self.connector_page = connector_page
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        footer = QHBoxLayout()
        footer.addStretch()
        footer.addWidget(close_btn)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(connector_page)
        layout.addLayout(footer)


class ScanProgressDialog(FloatingCard):
    """The scanning screen: a large radar sweep and the current phrase, centred, with a Cancel button."""
    CENTERED = True
    cancelled = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModal)
        self.setFixedWidth(520)
        self._quiet = False
        self.phase_index = 0

        self.spinner = RadarSpinner(size=170)
        self.phrase_label = QLabel()
        self.phrase_label.setObjectName("phrase")
        self.phrase_label.setAlignment(Qt.AlignCenter)
        self.phrase_label.setWordWrap(True)
        self.phrase_label.setMinimumHeight(60)
        note = QLabel("Sample data replay")
        note.setObjectName("muted")
        note.setAlignment(Qt.AlignCenter)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)

        layout = QVBoxLayout(self.card)
        layout.setContentsMargins(32, 32, 32, 28)
        layout.setSpacing(10)
        layout.addWidget(self.spinner, 0, Qt.AlignHCenter)
        layout.addSpacing(6)
        layout.addWidget(self.phrase_label)
        layout.addWidget(note)
        layout.addSpacing(10)
        layout.addWidget(self.cancel_btn, 0, Qt.AlignHCenter)

    def set_phase(self, index):
        self.phase_index = index

    def set_phrase(self, text):
        self.phrase_label.setText(text)

    def finish(self):
        """Close because the scan finished (not because the user cancelled)."""
        self._quiet = True
        self.accept()

    def reject(self):
        if not self._quiet:
            self.cancelled.emit()
        super().reject()


class ScanResultDialog(FloatingCard):
    """Result card shown when a scan finishes: red, amber or green, with a count per severity.
    All its text is one size."""
    TEXT_SIZE = 18
    BANNERS = {  # level: (background, border, text colour, icon)
        "high": ("#2A1010", "#6B2A2A", "#F87171", "⚠"),
        "other": ("#2A2410", "#6B5A1F", "#F5C451", "⚠"),
        "none": ("#0F2A1C", "#1F5A38", "#4ADE80", "✓"),
    }
    CHIPS = SEVERITY_COLORS
    DEFAULT_CHIP = ("#172A47", "#9FB3CC")

    def __init__(self, parent, findings):
        super().__init__(parent)
        self.setWindowModality(Qt.NonModal)  # the table behind stays usable
        self.setFixedWidth(580)
        self.level = result_level(findings)
        background, border, colour, icon = self.BANNERS[self.level]
        count = len(findings)
        if count == 0:
            text = "No vulnerabilities found"
        else:
            text = f"{count} {'vulnerability' if count == 1 else 'vulnerabilities'} detected"
        size = f"font-size: {self.TEXT_SIZE}px;"

        banner = QFrame()
        banner.setStyleSheet(f"background: {background}; border: 1px solid {border}; border-radius: 12px;")
        self.banner_label = QLabel(f"{icon}  {text}")
        self.banner_label.setStyleSheet(
            f"color: {colour}; {size} font-weight: 600; border: 0; background: transparent;")
        banner_box = QVBoxLayout(banner)
        banner_box.setContentsMargins(16, 12, 16, 12)
        banner_box.addWidget(self.banner_label)

        chips = QHBoxLayout()
        chips.setSpacing(8)
        self.chips = []
        for tier, n in severity_summary(findings):
            chip_bg, chip_fg = self.CHIPS.get(tier, self.DEFAULT_CHIP)
            chip = QLabel(f"{n} {tier}")
            chip.setStyleSheet(
                f"background: {chip_bg}; color: {chip_fg}; border-radius: 12px; padding: 3px 12px; {size}")
            chips.addWidget(chip)
            self.chips.append(chip)
        chips.addStretch()

        note = QLabel("Sample results")
        note.setStyleSheet(f"color: #8CA3C0; {size} background: transparent;")
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.reject)
        self.view_btn = QPushButton("View findings")
        self.view_btn.setObjectName("primary")
        self.view_btn.clicked.connect(self.accept)
        self.view_btn.setVisible(count > 0)
        footer = QHBoxLayout()
        footer.addWidget(note)
        footer.addStretch()
        footer.addWidget(self.close_btn)
        footer.addWidget(self.view_btn)

        layout = QVBoxLayout(self.card)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        layout.addWidget(banner)
        if self.chips:
            layout.addLayout(chips)
        layout.addSpacing(4)
        layout.addLayout(footer)


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
        self.phrase_timer = QTimer(self)
        self.phrase_timer.timeout.connect(self._rotate_phrase)
        self.phrases = PhraseRotator()
        self.progress = None  # the scanning popup while a scan runs
        self._dim = None  # darkens the window behind it
        self.result_dialog = None
        self._phase = 0

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
        self.table.setItemDelegate(SeverityRowDelegate(self.table))
        self.table.itemSelectionChanged.connect(self._refresh_detail)
        self.tracker = SeverityTracker()
        self.repo_chart = BurndownChart(compact=True)
        chart_card = QFrame()
        chart_card.setObjectName("card")
        chart_card.setFixedWidth(200)
        chart_box = QVBoxLayout(chart_card)
        chart_box.setContentsMargins(8, 8, 8, 8)
        chart_box.setSpacing(2)
        chart_heading = QLabel("This repo")
        chart_heading.setObjectName("severityHeading")
        chart_note = QLabel("Open findings (sample)")
        chart_note.setObjectName("severityDetail")
        chart_note.setWordWrap(True)
        chart_box.addWidget(chart_heading)
        chart_box.addWidget(self.repo_chart, 1)
        chart_box.addWidget(chart_note)
        side = QVBoxLayout()
        side.setSpacing(12)
        side.addWidget(self.tracker)
        side.addWidget(chart_card, 1)
        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self.table, 1)
        body.addLayout(side)

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
        self.log_toggle = QPushButton("▾ Scan log")
        self.log_toggle.setObjectName("link")
        self.log_toggle.setCursor(Qt.PointingHandCursor)
        self.log_toggle.setToolTip("Show or hide the scan log.")
        self.log_toggle.clicked.connect(self._toggle_log)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        layout.addLayout(top)
        layout.addLayout(body, 2)
        layout.addWidget(self.detail)
        layout.addWidget(self.log_toggle, 0, Qt.AlignLeft)
        layout.addWidget(self.output, 1)

        self._refresh_detail()

    # Page states
    def reset(self):
        """Blank page for a new scan."""
        self.timer.stop()
        self._close_progress()
        self._close_result()
        self._set_inputs_editable(True)
        self.repo.clear()
        self.demo.setChecked(True)
        self._fill_table([])
        self.repo_chart.set_points([])
        self.output.clear()
        self._refresh_detail()

    def show_record(self, record):
        """Read-only view of a past scan."""
        self.timer.stop()
        self._close_progress()
        self._close_result()
        self.repo.setText(record.repo)
        self.demo.setChecked(record.mode == "Demo")
        self._fill_table(record.findings)
        self.repo_chart.set_points(burndown_series(record.repo))
        self.output.setPlainText("\n".join(record.output))
        self._set_inputs_editable(False)

    def _toggle_log(self):
        show = self.output.isHidden()
        self.output.setVisible(show)
        self.log_toggle.setText("▾ Scan log" if show else "▸ Scan log")

    def showEvent(self, event):
        super().showEvent(event)
        self.table.resizeRowsToContents()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.table.resizeRowsToContents()

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
        self._close_result()
        self._fill_table([])
        self.repo_chart.set_points([])
        self.output.clear()
        self.scan_btn.setEnabled(False)
        self._line_index = 0
        self._run_output = self._output_for_model()
        self._phase = 0
        self.phrases = PhraseRotator()
        self._open_progress()
        self.timer.start(self.REPLAY_INTERVAL_MS)
        self.phrase_timer.start(self.PHRASE_INTERVAL_MS)

    # Scanning popup and result card
    REPLAY_INTERVAL_MS = 300
    PHRASE_INTERVAL_MS = 2000

    def _open_progress(self):
        self._close_progress()
        self.progress = ScanProgressDialog(self)
        self.progress.cancelled.connect(self._cancel_scan)
        self.progress.set_phase(self._phase)
        self.progress.set_phrase(self.phrases.next(self._phase))
        window = self.window()
        if window is not self:
            self._dim = DimOverlay(window)
        self.progress.show()

    def _remove_dim(self):
        if self._dim is not None:
            dim, self._dim = self._dim, None
            dim.dismiss()

    def _close_progress(self):
        self.phrase_timer.stop()
        self._remove_dim()
        if self.progress is not None:
            dialog, self.progress = self.progress, None
            dialog.finish()
            dialog.deleteLater()

    def _close_result(self):
        if self.result_dialog is not None:
            dialog, self.result_dialog = self.result_dialog, None
            dialog.close()
            dialog.deleteLater()

    def _rotate_phrase(self):
        if self.progress is not None:
            self.progress.set_phrase(self.phrases.next(self._phase))

    def _cancel_scan(self):
        """The user cancelled the scanning popup (a demo replay just stops)."""
        self.timer.stop()
        self.phrase_timer.stop()
        self._remove_dim()
        dialog, self.progress = self.progress, None
        if dialog is not None:
            dialog.deleteLater()
        self._fill_table([])
        self.output.setPlainText("Scan cancelled.")
        self.scan_btn.setEnabled(True)

    def _show_result(self, findings):
        self.result_dialog = ScanResultDialog(self, findings)
        self.result_dialog.accepted.connect(self.table.setFocus)
        self.result_dialog.show()

    def _output_for_model(self):
        model = self.model_box.currentText()
        return [line.replace("{model_id}", MODEL_IDS.get(model, model)) for line in self.sample_output]

    def _next_line(self):
        if self._line_index < len(self._run_output):
            line = self._run_output[self._line_index]
            self.output.appendPlainText(line)
            self._line_index += 1
            phase = phase_of_line(line, self._phase)
            if phase != self._phase:
                self._phase = phase
                if self.progress is not None:
                    self.progress.set_phase(phase)
                    self.progress.set_phrase(self.phrases.next(phase))
            return
        self.timer.stop()
        self._close_progress()
        # Copies, so a decision on one scan never changes the sample data or other scans.
        findings = [replace(f) for f in self.sample_findings]
        self._fill_table(findings)
        self.repo_chart.set_points(burndown_series(self.repo.text().strip() or REPO_URL))
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
        self._show_result(findings)

    def _fill_table(self, findings):
        self.tracker.update_counts(findings)
        # A severity outside SEVERITY_ORDER sorts last instead of raising.
        findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity)
                          if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER))
        self._rows = findings
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            colours = SEVERITY_COLORS.get(f.severity)
            for col, value in enumerate([f.id, f.severity, f.title, f.location, f.status]):
                item = QTableWidgetItem(value)
                if colours:
                    item.setBackground(QColor(colours[0]))
                    item.setForeground(QColor(colours[1]))
                self.table.setItem(row, col, item)
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
    HOME, HISTORY, SCAN, STATS = 0, 1, 2, 3
    MIN_ZOOM = 0.7
    MAX_ZOOM = 2.0
    DEFAULT_ZOOM = 1.0
    ZOOM_STEP = 0.1

    def __init__(self, settings=None):
        super().__init__()
        self.app_settings = settings if settings is not None else QSettings("VulnHunter", "VulnGUI")
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
        self.stack = QStackedWidget()
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.history_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.stats_page)
        self._page_history = [self.HOME]
        self._page_history_position = 0
        self.home_page.stats_requested.connect(self.show_stats)

        # API settings live in a popup opened from the gear icon, not on a page of their own.
        self.connector_page = ApiConnectorPage()
        self.connector_page.connected.connect(self.on_llm_connected)
        self.connector_page.disconnected.connect(self.on_llm_disconnected)
        self.connector_page.connect_failed.connect(self.on_llm_connect_failed)
        self.connector_page.api_key.textChanged.connect(self._on_api_key_edited)
        self.settings_dialog = ApiSettingsDialog(self, self.connector_page)
        self.connected_provider = None
        self.reminder = None

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
        home.setMinimumSize(300, 52)
        home.setCursor(Qt.PointingHandCursor)
        home.clicked.connect(self.show_home)
        self.home_button = home

        self.sample_tag = QLabel("Sample data")
        self.sample_tag.setObjectName("sampleTag")
        self.sample_tag.setToolTip("Every scan and chart in this app uses invented sample data.")
        self.status_pill = StatusPill()
        self.status_pill.clicked.connect(self.show_api_settings)
        self.help_button = QPushButton("?")
        self.help_button.setObjectName("iconButton")
        self.help_button.setCursor(Qt.PointingHandCursor)
        self.help_button.setToolTip("Getting started")
        self.help_button.clicked.connect(self.show_getting_started)
        status_cluster = QWidget()
        status_layout = QHBoxLayout(status_cluster)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(12)
        status_layout.addWidget(self.sample_tag)
        status_layout.addWidget(self.status_pill)
        status_layout.addWidget(self.help_button)

        # Equal stretch on both sides keeps the home button centred.
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)
        header_layout.addWidget(navigation, 1, Qt.AlignLeft | Qt.AlignVCenter)
        header_layout.addWidget(home, 0)
        header_layout.addWidget(status_cluster, 1, Qt.AlignRight | Qt.AlignVCenter)
        self._update_navigation_buttons()

        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(header)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.home_page.history_requested.connect(self.show_history)
        self.home_page.new_scan_requested.connect(self.new_scan)
        self.history_page.new_scan.connect(self.new_scan)
        self.history_page.record_selected.connect(self.open_record)
        self.scan_page.finished.connect(self.add_record)
        self.history_page.refresh(self.history)
        self._apply_zoom(self.DEFAULT_ZOOM)

    def show_home(self):
        self._navigate_to(self.HOME)

    def show_stats(self):
        self._navigate_to(self.STATS)

    def show_api_settings(self):
        self.settings_dialog.show()
        self.settings_dialog.raise_()
        self.settings_dialog.activateWindow()

    def on_llm_connected(self, provider_key, provider_label):
        self.connected_provider = (provider_key, provider_label)
        self.status_pill.set_state("ok", f"Connected to {provider_label}")

    def on_llm_disconnected(self):
        self.connected_provider = None
        self.status_pill.set_state("off")

    def on_llm_connect_failed(self, message):
        self.connected_provider = None
        self.status_pill.set_state("error", f"The key was rejected: {message}")

    def _on_api_key_edited(self, text):
        # Clearing the key after a rejection goes back to the pulsing "not connected" state.
        if not text.strip() and self.status_pill.state() == "error":
            self.on_llm_disconnected()

    def show_getting_started(self):
        """Open the Getting started popup on demand, even if the launch reminder was turned off."""
        dialog = GettingStartedDialog(self)
        dialog.dont_show.setChecked(reminder_hidden(self.app_settings))
        dialog.finished.connect(lambda _result, d=dialog: self._on_reminder_closed(d))
        self.reminder = dialog
        dialog.show()
        return dialog

    def maybe_show_reminder(self):
        """Show the Getting started reminder on launch unless the user opted out. Returns the dialog or None."""
        if reminder_hidden(self.app_settings):
            return None
        return self.show_getting_started()

    def _on_reminder_closed(self, dialog):
        # Ticking the box turns the launch reminder off; unticking it (via the ? button) turns it back on.
        set_reminder_hidden(self.app_settings, dialog.dont_show.isChecked())

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
    QApplication.setAttribute(Qt.AA_DisableWindowContextHelpButton, True)  # no '?' on dialogs
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.maybe_show_reminder()
    sys.exit(app.exec_())
