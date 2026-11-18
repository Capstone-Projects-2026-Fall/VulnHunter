import sys

if sys.version_info < (3, 11):  # the agent config this GUI loads needs tomllib
    sys.exit(f"VulnHunter GUI needs Python 3.11 or newer (this is {sys.version.split()[0]}). "
             "Install a newer Python, then run it again.")

import math
import os
import random
import re
from urllib.parse import quote
from dataclasses import replace
from datetime import datetime
from pathlib import Path

# main_gui.py is in VulnHunter/gui/, so the repo root is one level up
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import QEvent, QPoint, QPointF, QRectF, QSettings, Qt, QTimer, QUrl, pyqtSignal
from PyQt5.QtGui import (
    QBrush, QColor, QConicalGradient, QDesktopServices, QFont, QPainter, QPainterPath, QPen,
    QTextCursor, QTextFormat,
)
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QPlainTextEdit, QPushButton, QScrollArea, QStackedWidget, QStyle, QStyledItemDelegate,
    QStyleOptionViewItem, QTabBar, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
    QSizePolicy,
)

from gui.data.mock_data import (
    ACCEPT_REASONS, ALL_REPOS, BURNDOWN_BY_REPO, DISABLED_MODELS, HUNT_PHASE, IGNORE_REASONS,
    MODEL_IDS, REPO_URL, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SCAN_PHASES, SCAN_PHRASES, SEED_HISTORY,
    SEVERITY_ORDER, ScanRecord, burndown_series, burndown_totals, code_url, phase_of_line,
    burndown_repo_key, cwe_name, cwe_url, open_by_severity, result_level, sample_fix, sample_repo_findings,
    sample_snippet, severity_summary, split_location,
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
QFrame#card[hover="true"] { border: 1px solid #2C4A73; }
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
QTabBar::tab {
    background: transparent; color: #8CA3C0; padding: 8px 4px; margin-right: 26px; border: 0;
    border-bottom: 2px solid transparent; font-weight: 600;
}
QTabBar::tab:selected { color: #E6EEF8; border-bottom: 2px solid #38BDF8; }
QTabBar::tab:hover { color: #E6EEF8; }
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
    "High+": ("#4A1220", "#F0444F"),  # dark red: a deeper red than High, in the rows and the counts
    "High": ("#5E1F24", "#FF9494"),  # red
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


class Breadcrumb(QWidget):
    """A visible way back: '<- Scan History / github.com/testrepo'."""
    back_clicked = pyqtSignal()

    def __init__(self, back_text, current=""):
        super().__init__()
        self.back_btn = QPushButton(f"← {back_text}")
        self.back_btn.setObjectName("link")
        self.back_btn.setCursor(Qt.PointingHandCursor)
        self.back_btn.setToolTip(f"Back to {back_text}")
        self.back_btn.clicked.connect(self.back_clicked)
        self.separator = QLabel("/")
        self.separator.setObjectName("muted")
        self.current = QLabel()
        self.current.setObjectName("muted")
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        row.addWidget(self.back_btn)
        row.addWidget(self.separator)
        row.addWidget(self.current)
        row.addStretch()
        self.set_current(current)

    def set_current(self, text):
        self.current.setText(text)
        self.separator.setVisible(bool(text))
        self.current.setVisible(bool(text))


class ClickableCard(QFrame):
    """A card that behaves like a button: pointing hand, an outline on hover, and a clicked signal."""
    clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        self.setCursor(Qt.PointingHandCursor)
        self.setProperty("hover", False)

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

class GettingStartedBanner(QFrame):
    """The first steps, as a dismissible card on the home page (not a popup)."""
    closed = pyqtSignal(bool)  # True when "Don't show this again" was ticked
    STEPS = ["Click the status pill to add your API key",
             "Start a New Scan, or open Scan History",
             "Review findings, then Fix, Accept or Ignore"]

    def __init__(self):
        super().__init__()
        self.setObjectName("card")
        title = QLabel("Getting started")
        title.setStyleSheet("font-weight: 600;")
        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("iconButton")
        self.close_btn.setToolTip("Dismiss")
        self.close_btn.clicked.connect(self._close)
        header = QHBoxLayout()
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.close_btn)

        steps = QHBoxLayout()
        steps.setSpacing(28)
        for number, text in enumerate(self.STEPS, 1):
            badge = QLabel(str(number))
            badge.setFixedSize(26, 26)
            badge.setAlignment(Qt.AlignCenter)
            badge.setStyleSheet("background: #38BDF8; color: #05101F; border-radius: 13px; font-weight: 600;")
            label = QLabel(text)
            label.setWordWrap(True)
            step = QHBoxLayout()
            step.setSpacing(10)
            step.addWidget(badge)
            step.addWidget(label, 1)
            steps.addLayout(step, 1)
        self.dont_show = QCheckBox("Don't show this again")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 12, 12, 14)
        layout.setSpacing(8)
        layout.addLayout(header)
        layout.addLayout(steps)
        layout.addWidget(self.dont_show)

    def _close(self):
        self.hide()
        self.closed.emit(self.dont_show.isChecked())


class HomePage(QWidget):
    history_requested = pyqtSignal()
    reports_requested = pyqtSignal()
    new_scan_requested = pyqtSignal()
    getting_started_closed = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setObjectName("homePage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(HOME_QSS)

        self.getting_started = GettingStartedBanner()
        self.getting_started.closed.connect(self.getting_started_closed)

        heading = QLabel("Welcome back, dev")
        heading.setObjectName("homeHeading")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub = QLabel("Review findings, track reports, or start a scan.")
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
            ("◔", "Reports", "Burndown, severity and provider comparison.", self.reports_requested),
        ]:
            card = ModuleCard(icon, title, desc)
            card.clicked.connect(signal.emit)
            cards.addWidget(card, 3)
        cards.addStretch(1)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 28, 48, 36)
        layout.setSpacing(0)
        layout.addWidget(self.getting_started)
        layout.addStretch(1)
        layout.addWidget(heading)
        layout.addSpacing(8)
        layout.addWidget(sub)
        layout.addSpacing(26)
        layout.addWidget(self.new_scan_btn, 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addSpacing(30)
        layout.addLayout(cards)
        layout.addStretch(2)

    def set_getting_started_visible(self, visible):
        self.getting_started.setVisible(visible)


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


class ReportsPage(QWidget):
    """Reports: Overview, Providers and Quality tabs. Everything here is invented sample data."""
    back_requested = pyqtSignal()
    new_scan_requested = pyqtSignal()
    TABS = ("Overview", "Providers", "Quality")
    BAR_WIDTH = 220

    def __init__(self):
        super().__init__()
        self.breadcrumb = Breadcrumb("Home", "Reports")
        self.breadcrumb.back_clicked.connect(self.back_requested)
        title = QLabel("Reports")
        title.setObjectName("statsTitle")
        self.tabs = QTabBar()
        self.tabs.setDrawBase(False)
        self.tabs.setExpanding(False)
        for name in self.TABS:
            self.tabs.addTab(name)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_overview())
        self.pages.addWidget(self._build_providers())
        self.pages.addWidget(self._build_quality())
        self.tabs.currentChanged.connect(self.pages.setCurrentIndex)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(10)
        layout.addWidget(self.breadcrumb)
        layout.addWidget(title)
        layout.addWidget(self.tabs, 0, Qt.AlignLeft)
        layout.addWidget(self.pages, 1)
        self._update()

    @staticmethod
    def _card(title, subtitle):
        card = QFrame()
        card.setObjectName("card")
        box = QVBoxLayout(card)
        box.setContentsMargins(16, 14, 16, 14)
        box.setSpacing(4)
        heading = QLabel(title)
        heading.setStyleSheet("font-weight: 600;")
        note = QLabel(subtitle)
        note.setObjectName("muted")
        box.addWidget(heading)
        box.addWidget(note)
        return card, box

    def _build_overview(self):
        page = QWidget()
        self.repo_box = QComboBox()
        self.repo_box.addItem(ALL_REPOS)
        self.repo_box.addItems(list(BURNDOWN_BY_REPO))
        self.repo_box.setToolTip("Show the reports for all repos or for one.")
        self.repo_box.currentIndexChanged.connect(self._update)
        self.reset_btn = QPushButton("Reset to default")
        self.reset_btn.setObjectName("link")
        self.reset_btn.setCursor(Qt.PointingHandCursor)
        self.reset_btn.clicked.connect(lambda: self.repo_box.setCurrentIndex(0))
        filters = QHBoxLayout()
        filters.addWidget(self.repo_box)
        filters.addStretch()
        filters.addWidget(self.reset_btn)

        strip = QHBoxLayout()
        strip.setSpacing(12)
        self.card_values = {}
        for name in ("Open", "Closed", "Total", "Cost per confirmed finding"):
            card = QFrame()
            card.setObjectName("card")
            box = QVBoxLayout(card)
            value = QLabel("n/a" if name.startswith("Cost") else "0")
            value.setObjectName("cardValue")
            box.addWidget(value)
            box.addWidget(QLabel(name))
            if name.startswith("Cost"):
                card.setToolTip("Needs real scan runs with token usage, so it is not available on sample data.")
            self.card_values[name] = value
            strip.addWidget(card)

        burn_card, burn_box = self._card("Burndown", "Open findings over time (dashed: ideal burndown)")
        self.chart = BurndownChart()
        burn_box.addWidget(self.chart, 1)
        sev_card, sev_box = self._card("Findings by severity", "Current open findings")
        self.severity_values = {}
        self.severity_bars = {}
        for tier in SEVERITY_ORDER:
            name = QLabel(tier)
            name.setFixedWidth(130)
            bar = QFrame()
            bar.setFixedHeight(18)
            bar.setStyleSheet(f"background: {SEVERITY_COLORS[tier][1]}; border-radius: 4px;")
            value = QLabel("0")
            row = QHBoxLayout()
            row.addWidget(name)
            row.addWidget(bar)
            row.addStretch()
            row.addWidget(value)
            sev_box.addLayout(row)
            self.severity_bars[tier] = bar
            self.severity_values[tier] = value
        sev_box.addStretch()
        grid = QHBoxLayout()
        grid.setSpacing(12)
        grid.addWidget(burn_card, 3)
        grid.addWidget(sev_card, 2)
        note = QLabel("Sample data, not real scan results.")
        note.setObjectName("muted")

        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(12)
        layout.addLayout(filters)
        layout.addLayout(strip)
        layout.addLayout(grid, 1)
        layout.addWidget(note)
        return page

    def _empty_state(self, title, text, button_text=None):
        page = QWidget()
        card = QFrame()
        card.setObjectName("card")
        box = QVBoxLayout(card)
        box.setContentsMargins(32, 36, 32, 36)
        box.setSpacing(10)
        heading = QLabel(title)
        heading.setObjectName("title")
        heading.setAlignment(Qt.AlignCenter)
        body = QLabel(text)
        body.setObjectName("muted")
        body.setAlignment(Qt.AlignCenter)
        body.setWordWrap(True)
        box.addWidget(heading)
        box.addWidget(body)
        button = None
        if button_text:
            button = QPushButton(button_text)
            button.setObjectName("primary")
            box.addWidget(button, 0, Qt.AlignHCenter)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.addWidget(card)
        layout.addStretch()
        return page, button

    def _build_providers(self):
        page, button = self._empty_state(
            "No provider runs yet",
            "Run the same repository with two providers to compare tokens, cost and time side by side.",
            "Start a comparison")
        button.clicked.connect(self.new_scan_requested)
        self.providers_button = button
        return page

    def _build_quality(self):
        page, _button = self._empty_state(
            "No benchmark results yet",
            "Scanner quality will show precision, recall and misses once a benchmark has been run.")
        return page

    def _update(self, *_args):
        repo = self.repo_box.currentText()
        series = burndown_series(repo)
        self.chart.set_points(series)
        open_now, closed, total = burndown_totals(series)
        for name, value in (("Open", open_now), ("Closed", closed), ("Total", total)):
            self.card_values[name].setText(str(value))
        counts = open_by_severity(sample_repo_findings(repo))
        peak = max(counts.values(), default=0)
        for tier in SEVERITY_ORDER:
            n = counts.get(tier, 0)
            self.severity_values[tier].setText(str(n))
            self.severity_bars[tier].setVisible(n > 0)
            if n:
                self.severity_bars[tier].setFixedWidth(max(8, int(self.BAR_WIDTH * n / peak)))


ALL_MODELS = "All models"


class HistoryPage(QWidget):
    new_scan = pyqtSignal()
    back_requested = pyqtSignal()
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
        self.breadcrumb = Breadcrumb("Home", "Scan History")
        self.breadcrumb.back_clicked.connect(self.back_requested)
        layout.addWidget(self.breadcrumb)
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
    """Darkens the window behind a popup and swallows clicks (it reports them through `clicked`)."""
    clicked = pyqtSignal()

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

    def mousePressEvent(self, event):
        self.clicked.emit()

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
    CARD_WIDTH = 520
    CARD_MIN_HEIGHT = 410  # the scanning screen and the result card are the same size

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setStyleSheet("QDialog { background: transparent; }")
        self.setFixedWidth(self.CARD_WIDTH)
        self.card = QFrame(self)
        self.card.setObjectName("popupCard")
        self.card.setMinimumHeight(self.CARD_MIN_HEIGHT)
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


class ApiPopover(FloatingCard):
    """The API settings, as a small popover under the status pill (Esc or a click outside closes it)."""
    CARD_WIDTH = 400
    CARD_MIN_HEIGHT = 0

    def __init__(self, parent, connector_page, pill):
        super().__init__(parent)
        self.pill = pill
        self.connector_page = connector_page
        self.setWindowModality(Qt.NonModal)
        connector_page.set_compact(True)
        layout = QVBoxLayout(self.card)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(connector_page)

    def place(self):
        corner = self.pill.mapToGlobal(QPoint(self.pill.width(), self.pill.height()))
        self.move(corner.x() - self.width(), corner.y() + 8)


class ScanProgressDialog(FloatingCard):
    """The scanning screen: a large radar sweep and the current phrase, centred, with a Cancel button."""
    CENTERED = True
    cancelled = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModal)
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


class ResultBanner(QFrame):
    """An inline summary after a scan: red, amber or green, with a count per severity. Dismissible."""
    BANNERS = {  # level: (background, border, text colour, icon)
        "high": ("#2A1010", "#6B2A2A", "#F87171", "⚠"),
        "other": ("#2A2410", "#6B5A1F", "#F5C451", "⚠"),
        "none": ("#0F2A1C", "#1F5A38", "#4ADE80", "✓"),
    }

    def __init__(self):
        super().__init__()
        self.setObjectName("resultBanner")
        self.level = None
        self.label = QLabel()
        self.label.setWordWrap(True)
        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("iconButton")
        self.close_btn.setToolTip("Dismiss")
        self.close_btn.clicked.connect(self.hide)
        row = QHBoxLayout(self)
        row.setContentsMargins(16, 8, 8, 8)
        row.addWidget(self.label, 1)
        row.addWidget(self.close_btn)
        self.hide()

    def show_findings(self, findings):
        self.level = result_level(findings)
        background, border, colour, icon = self.BANNERS[self.level]
        count = len(findings)
        if count == 0:
            headline = "No vulnerabilities found"
        else:
            headline = f"{count} {'vulnerability' if count == 1 else 'vulnerabilities'} detected"
        summary = ", ".join(f"{n} {tier}" for tier, n in severity_summary(findings))
        parts = [f"{icon}  {headline}"] + ([summary] if summary else []) + ["sample results"]
        self.label.setText("  |  ".join(parts))
        self.setStyleSheet(
            f"QFrame#resultBanner {{ background: {background}; border: 1px solid {border}; border-radius: 12px; }}"
            f"QLabel {{ color: {colour}; background: transparent; font-size: 18px; font-weight: 600; }}"
            f"QPushButton {{ color: {colour}; }}")
        self.show()


def editor_uri(repo_text, location):
    """vscode:// link to the flagged line, only when the repo is an existing local folder holding the file."""
    repo_text = (repo_text or "").strip()
    if not repo_text or not os.path.isdir(repo_text):
        return ""
    path, line = split_location(location)
    full = (Path(repo_text) / path).resolve()
    if not path or not full.is_file():
        return ""
    return f"vscode://file/{quote(full.as_posix(), safe='/:')}:{line or 1}"


class ScanPage(QWidget):
    finished = pyqtSignal(object)  # emits a ScanRecord
    repo_chart_requested = pyqtSignal(str)  # the small burndown was clicked: show the big one for this repo
    back_requested = pyqtSignal()
    SIDE_WIDTH = 340

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
        self._chart_repo = None
        self._decision_kind = None
        self._form_finding = None
        self._phase = 0

        self.breadcrumb = Breadcrumb("Scan History", "New scan")
        self.breadcrumb.back_clicked.connect(self.back_requested)
        self.banner = ResultBanner()

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
        self.table.cellClicked.connect(self._on_row_clicked)

        # Right column: overview (severity counts + repo burndown) or the clicked finding.
        self.tracker = SeverityTracker()
        self.repo_chart = BurndownChart(compact=True)
        chart_card = ClickableCard()
        chart_card.setToolTip("Click for a bigger chart")
        chart_card.clicked.connect(self._open_repo_chart)
        self.repo_chart_card = chart_card
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
        overview = QWidget()
        overview_box = QVBoxLayout(overview)
        overview_box.setContentsMargins(0, 0, 0, 0)
        overview_box.setSpacing(12)
        overview_box.addWidget(self.tracker)
        overview_box.addWidget(chart_card, 1)

        self.detail = self._build_detail_panel()
        self.side = QStackedWidget()
        self.side.setFixedWidth(self.SIDE_WIDTH)
        self.detail_scroll = QScrollArea()  # the panel scrolls when the decision form makes it tall
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.NoFrame)
        self.detail_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.detail_scroll.setWidget(self.detail)
        self.side.addWidget(overview)
        self.side.addWidget(self.detail_scroll)

        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self.table, 1)
        body.addWidget(self.side)

        # Output: collapsed until asked for
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumHeight(180)
        self.output.hide()
        self.log_toggle = QPushButton("▸ Scan log")
        self.log_toggle.setObjectName("link")
        self.log_toggle.setCursor(Qt.PointingHandCursor)
        self.log_toggle.setToolTip("Show or hide the scan log.")
        self.log_toggle.clicked.connect(self._toggle_log)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(12)
        layout.addWidget(self.breadcrumb)
        layout.addWidget(self.banner)
        layout.addLayout(top)
        layout.addLayout(body, 1)
        layout.addWidget(self.log_toggle, 0, Qt.AlignLeft)
        layout.addWidget(self.output)

        self._refresh_detail()

    def _build_detail_panel(self):
        """The clicked finding: details and actions. Fix, Accept, Ignore, Verify and Report are
        mocked: they work on sample data only and never touch a repository."""
        panel = QFrame()
        panel.setObjectName("card")
        self.detail_heading = QLabel()
        self.detail_heading.setStyleSheet("font-weight: 600;")
        self.detail_close = QPushButton("✕")
        self.detail_close.setObjectName("iconButton")
        self.detail_close.setToolTip("Close")
        self.detail_close.clicked.connect(self._close_detail)
        heading_row = QHBoxLayout()
        heading_row.addWidget(self.detail_heading, 1)
        heading_row.addWidget(self.detail_close)

        self.cwe_link = QPushButton()
        self.cwe_link.setObjectName("link")
        self.cwe_link.setCursor(Qt.PointingHandCursor)
        self.cwe_link.clicked.connect(self._open_cwe)
        self.detail_title = QLabel()
        self.detail_title.setWordWrap(True)
        self.location_label = QLabel()
        self.location_label.setObjectName("muted")
        self.location_label.setWordWrap(True)
        self.editor_btn = QPushButton("Open in editor")
        self.editor_btn.clicked.connect(self._open_in_editor)
        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setToolTip("Copy the file location.")
        self.copy_btn.clicked.connect(self._copy_location)
        link_row = QHBoxLayout()
        link_row.setSpacing(8)
        link_row.addWidget(self.editor_btn)
        link_row.addWidget(self.copy_btn)
        link_row.addStretch()

        self.code_view = QPlainTextEdit()
        self.code_view.setReadOnly(True)
        self.code_view.setFixedHeight(150)
        self.code_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.code_view.setStyleSheet("font-family: Consolas, 'Courier New', monospace;")
        fix_heading = QLabel("Proposed fix (sample)")
        fix_heading.setStyleSheet("font-weight: 600;")
        self.fix_text = QLabel()
        self.fix_text.setWordWrap(True)
        self.fix_text.setObjectName("muted")
        self.action_note = QLabel()
        self.action_note.setWordWrap(True)
        self.action_note.setObjectName("muted")
        self.action_note.hide()
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
        # A widget's own stylesheet beats inherited ones, so size each button here.
        for btn in (self.fix_btn, self.accept_btn, self.ignore_btn, self.verify_btn, self.report_btn,
                    self.editor_btn, self.copy_btn):
            btn.setStyleSheet("padding: 8px 14px;")
        actions = QHBoxLayout()
        actions.setSpacing(8)
        for btn in (self.fix_btn, self.accept_btn, self.ignore_btn):
            actions.addWidget(btn)
        actions.addStretch()
        more = QHBoxLayout()
        more.setSpacing(8)
        more.addWidget(self.verify_btn)
        more.addWidget(self.report_btn)
        more.addStretch()

        # Inline form for Accept and Ignore
        self.decision_form = QFrame()
        self.decision_form.hide()
        self.decision_title = QLabel()
        self.decision_title.setStyleSheet("font-weight: 600;")
        self.decision_reason = QComboBox()
        self.decision_note = QPlainTextEdit()
        self.decision_note.setPlaceholderText("Context (optional)")
        self.decision_note.setFixedHeight(70)
        self.decision_save = QPushButton("Save decision")
        self.decision_save.setObjectName("primary")
        self.decision_save.setStyleSheet("padding: 8px 14px;")
        self.decision_save.clicked.connect(self._save_decision)
        self.decision_cancel = QPushButton("Cancel")
        self.decision_cancel.setStyleSheet("padding: 8px 14px;")
        self.decision_cancel.clicked.connect(self._cancel_decision)
        form_buttons = QHBoxLayout()
        form_buttons.addWidget(self.decision_save)
        form_buttons.addWidget(self.decision_cancel)
        form_buttons.addStretch()
        form = QVBoxLayout(self.decision_form)
        form.setContentsMargins(0, 4, 0, 0)
        form.setSpacing(6)
        form.addWidget(self.decision_title)
        form.addWidget(self.decision_reason)
        form.addWidget(self.decision_note)
        form.addLayout(form_buttons)

        box = QVBoxLayout(panel)
        box.setContentsMargins(14, 12, 14, 14)
        box.setSpacing(6)
        box.addLayout(heading_row)
        box.addWidget(self.cwe_link, 0, Qt.AlignLeft)
        box.addWidget(self.detail_title)
        box.addWidget(self.location_label)
        box.addLayout(link_row)
        box.addWidget(self.code_view)
        box.addWidget(fix_heading)
        box.addWidget(self.fix_text)
        box.addWidget(self.decision_label)
        box.addWidget(self.action_note)
        box.addLayout(actions)
        box.addLayout(more)
        box.addWidget(self.decision_form)
        box.addStretch()
        return panel

    # Page states
    def reset(self):
        """Blank page for a new scan."""
        self.timer.stop()
        self._close_progress()
        self.banner.hide()
        self._set_inputs_editable(True)
        self.repo.clear()
        self.demo.setChecked(True)
        self._fill_table([])
        self._set_repo_chart(None)
        self.output.clear()
        self.breadcrumb.set_current("New scan")
        self._refresh_detail()

    def show_record(self, record):
        """Read-only view of a past scan."""
        self.timer.stop()
        self._close_progress()
        self.banner.hide()
        self.repo.setText(record.repo)
        self.demo.setChecked(record.mode == "Demo")
        self._fill_table(record.findings)
        self._set_repo_chart(record.repo)
        self.output.setPlainText("\n".join(record.output))
        self.breadcrumb.set_current(record.repo)
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

    # The small per-repo burndown opens the big one on the Reports page
    def _set_repo_chart(self, repo):
        self._chart_repo = repo
        self.repo_chart.set_points(burndown_series(repo) if repo else [])

    def _open_repo_chart(self):
        if self._chart_repo:
            self.repo_chart_requested.emit(burndown_repo_key(self._chart_repo))

    # Finding panel: opens in the right column when a row is clicked (not when a scan selects row 0)
    def _on_row_clicked(self, _row, _column):
        if self._current_finding() is not None:  # the click has selected the row
            self._open_detail()

    def _open_detail(self):
        self._refresh_detail()
        self.side.setCurrentIndex(1)

    def _close_detail(self):
        self._cancel_decision()
        self.side.setCurrentIndex(0)

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
        self.banner.hide()
        self._fill_table([])
        self._set_repo_chart(None)
        self.output.clear()
        self.scan_btn.setEnabled(False)
        self._line_index = 0
        self._run_output = self._output_for_model()
        self._phase = 0
        self.phrases = PhraseRotator()
        self._open_progress()
        self.timer.start(self.REPLAY_INTERVAL_MS)
        self.phrase_timer.start(self.PHRASE_INTERVAL_MS)

    # Scanning popup
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
        self.banner.show_findings(findings)

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
        self._set_repo_chart(self.repo.text().strip() or REPO_URL)
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
        self.breadcrumb.set_current(record.repo)
        self.finished.emit(record)
        self._show_result(findings)

    def _fill_table(self, findings):
        self._close_detail()
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
        buttons = (self.fix_btn, self.accept_btn, self.ignore_btn, self.verify_btn, self.report_btn,
                   self.copy_btn)
        for btn in buttons:
            btn.setEnabled(finding is not None)
        if finding is None:
            self.detail_heading.setText("No finding selected")
            self.detail_title.setText("Select a finding to see its details and actions.")
            for widget in (self.cwe_link, self.location_label, self.decision_label, self.action_note):
                widget.hide()
            self.editor_btn.setEnabled(False)
            self.code_view.setPlainText("")
            self.fix_text.setText("")
            return
        self.detail_heading.setText(f"{finding.id}  |  {finding.severity}  |  {finding.status}")
        self.detail_title.setText(finding.title)
        url = cwe_url(finding.cwe)
        self.cwe_link.setVisible(bool(url))
        if url:
            name = cwe_name(finding.cwe)
            self.cwe_link.setText(f"{finding.cwe} {name} ↗" if name else f"{finding.cwe} ↗")
            self.cwe_link.setToolTip(url)
        self.location_label.setText(finding.location)
        self.location_label.show()
        self._editor_link = editor_uri(self.repo.text(), finding.location)
        self.editor_btn.setEnabled(bool(self._editor_link))
        self.editor_btn.setToolTip("Open the flagged line in VS Code." if self._editor_link else
                                   "Needs a local repository folder that contains this file.")
        self._show_code(finding)
        self.fix_text.setText(sample_fix(finding))
        if finding.decision:
            text = f"{finding.decision}: {finding.reason}"
            if finding.note:
                text += f". Context: {finding.note}"
            self.decision_label.setText(text)
            self.decision_label.show()
        else:
            self.decision_label.hide()

    def _show_code(self, finding):
        snippet = sample_snippet(finding)
        _path, flagged = split_location(finding.location)
        if not snippet:
            self.code_view.setPlainText("No sample code for this finding.")
            self.code_view.setExtraSelections([])
            return
        lines = [f"{'>' if number == flagged else ' '} {number:>4} | {text}" for number, text in snippet]
        self.code_view.setPlainText("\n".join(lines))
        selections = []
        for index, (number, _text) in enumerate(snippet):
            if number == flagged:
                selection = QTextEdit.ExtraSelection()
                selection.format.setBackground(QColor("#3B2A12"))
                selection.format.setProperty(QTextFormat.FullWidthSelection, True)
                selection.cursor = QTextCursor(self.code_view.document().findBlockByNumber(index))
                selections.append(selection)
        self.code_view.setExtraSelections(selections)

    def _refresh_status(self):
        """Put the selected finding's status back into its table row, then refresh the details."""
        rows = self.table.selectionModel().selectedRows()
        finding = self._current_finding()
        if finding is not None:
            self.table.item(rows[0].row(), 4).setText(finding.status)
        self._refresh_detail()

    def _open_cwe(self):
        finding = self._current_finding()
        if finding is not None and cwe_url(finding.cwe):
            QDesktopServices.openUrl(QUrl(cwe_url(finding.cwe)))

    def _open_in_editor(self):
        if getattr(self, "_editor_link", ""):
            QDesktopServices.openUrl(QUrl(self._editor_link))

    def _copy_location(self):
        finding = self._current_finding()
        if finding is not None:
            QApplication.clipboard().setText(finding.location)

    def _note(self, text):
        self.action_note.setText(text)
        self.action_note.setVisible(bool(text))

    # Mocked actions on the selected finding
    def _propose_fix(self):
        finding = self._current_finding()
        if finding is None:
            return
        if not finding.decision:
            finding.status = "Fix proposed"
        self._refresh_status()
        self._note("Sample fix proposal shown above. Mocked: a real Fix would create a branch, "
                   "write tests and open a pull request. Nothing was changed.")

    def _decide(self, kind):
        finding = self._current_finding()
        if finding is None:
            return
        self._decision_kind = kind
        self._form_finding = finding
        self.decision_title.setText(f"{kind}: {finding.id}")
        self.decision_reason.clear()
        self.decision_reason.addItems(ACCEPT_REASONS if kind == "Accept" else IGNORE_REASONS)
        self.decision_note.clear()
        self.decision_form.show()

    def _save_decision(self):
        finding = self._form_finding
        if finding is not None:
            decision = "Accepted" if self._decision_kind == "Accept" else "Ignored"
            apply_decision(finding, decision, self.decision_reason.currentText(),
                           self.decision_note.toPlainText())
            self._refresh_status()
        self._cancel_decision()

    def _cancel_decision(self):
        self._decision_kind = None
        self._form_finding = None
        self.decision_form.hide()

    def _not_implemented(self, name):
        self._note(f"{name} is not available in this demo yet.")


class MainWindow(QMainWindow):
    HOME, HISTORY, SCAN, REPORTS = 0, 1, 2, 3
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
        self.reports_page = ReportsPage()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.history_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.reports_page)
        self._page_history = [self.HOME]
        self._page_history_position = 0
        self.home_page.reports_requested.connect(self.show_reports)

        # API settings live in a popup opened from the gear icon, not on a page of their own.
        self.connector_page = ApiConnectorPage()
        self.connector_page.connected.connect(self.on_llm_connected)
        self.connector_page.disconnected.connect(self.on_llm_disconnected)
        self.connector_page.connect_failed.connect(self.on_llm_connect_failed)
        self.connector_page.api_key.textChanged.connect(self._on_api_key_edited)
        self.api_popover = None
        self.connected_provider = None

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
        self.history_page.back_requested.connect(self.show_home)
        self.scan_page.back_requested.connect(self.show_history)
        self.reports_page.back_requested.connect(self.show_home)
        self.reports_page.new_scan_requested.connect(self.new_scan)
        self.home_page.getting_started_closed.connect(self._on_getting_started_closed)
        self.history_page.record_selected.connect(self.open_record)
        self.scan_page.finished.connect(self.add_record)
        self.scan_page.repo_chart_requested.connect(self.show_repo_burndown)
        self.history_page.refresh(self.history)
        self._apply_zoom(self.DEFAULT_ZOOM)

    def show_home(self):
        self._navigate_to(self.HOME)

    def show_reports(self):
        self._navigate_to(self.REPORTS)

    def show_repo_burndown(self, repo):
        """Open the Reports page on one repo's burndown (the big version of the scan page's chart)."""
        self.reports_page.tabs.setCurrentIndex(0)
        self.reports_page.repo_box.setCurrentText(repo)
        self.show_reports()

    def show_api_settings(self):
        """Toggle the API settings popover under the status pill."""
        if self.api_popover is not None and self.api_popover.isVisible():
            self.api_popover.close()
            return
        if self.api_popover is None:
            self.api_popover = ApiPopover(self, self.connector_page, self.status_pill)
        self.api_popover.show()
        self.api_popover.raise_()

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
        """Go home and show the Getting started banner, even if it was turned off."""
        self.show_home()
        banner = self.home_page.getting_started
        banner.dont_show.setChecked(reminder_hidden(self.app_settings))
        self.home_page.set_getting_started_visible(True)
        return banner

    def maybe_show_reminder(self):
        """Show the Getting started banner on launch unless the user opted out."""
        visible = not reminder_hidden(self.app_settings)
        self.home_page.set_getting_started_visible(visible)
        return visible

    def _on_getting_started_closed(self, dont_show):
        # Ticking the box keeps the banner away on the next launch; unticking it (via ?) brings it back.
        set_reminder_hidden(self.app_settings, dont_show)

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

    def _close_popover_on_outside_click(self, event):
        popover = self.api_popover
        if popover is None or not popover.isVisible() or QApplication.activePopupWidget() is not None:
            return
        point = event.globalPos()
        inside_popover = popover.frameGeometry().contains(point)
        pill_rect = self.status_pill.rect().translated(self.status_pill.mapToGlobal(QPoint(0, 0)))
        if not inside_popover and not pill_rect.contains(point):
            popover.close()

    def eventFilter(self, obj, event):
        if event.type() == QEvent.MouseButtonPress:
            self._close_popover_on_outside_click(event)
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
