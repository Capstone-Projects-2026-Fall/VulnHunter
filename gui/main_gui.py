import sys

if sys.version_info < (3, 11):  # the agent config this GUI loads needs tomllib
    sys.exit(f"VulnHunter GUI needs Python 3.11 or newer (this is {sys.version.split()[0]}). "
             "Install a newer Python, then run it again.")

import json
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
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QGridLayout,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QPlainTextEdit, QPushButton, QScrollArea, QStackedWidget, QStyle, QStyledItemDelegate,
    QStyleOptionViewItem, QTabBar, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
    QSizePolicy,
)

from gui.data.mock_data import (
    ALL_REPOS, BURNDOWN_BY_REPO, DISABLED_MODELS, HUNT_PHASE, DISPUTE_REASONS,
    MODEL_IDS, REPO_URL, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SCAN_PHASES, SCAN_PHRASES, SEED_HISTORY,
    SEVERITY_ORDER, ScanRecord, burndown_series, burndown_totals, code_url, phase_of_line,
    burndown_repo_key, cwe_name, cwe_url, latest_scan_indexes, open_by_severity, result_level, sample_fix,
    sample_issue, sample_repo_findings, sample_snippet, severity_summary, split_location, status_group,
    STATUS_GROUPS, finding_sort_key, severity_rank,
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
    background: transparent; color: #8CA3C0; padding: 8px 16px; margin-right: 4px; border: 0;
    border-bottom: 2px solid transparent;
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
    # Scroll by pixels: the default scrolls a whole row per step, so a small adjustment would jump far.
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
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

    def set_back_text(self, back_text):
        self.back_btn.setText(f"← {back_text}")
        self.back_btn.setToolTip(f"Back to {back_text}")

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
             "Start a New Scan, or open Findings",
             "Review findings, then Fix, Accept or Dispute"]

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
    reports_requested = pyqtSignal()
    new_scan_requested = pyqtSignal()
    findings_requested = pyqtSignal()
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
            ("☰", "Findings", "All findings and past scans, by status.", self.findings_requested),
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
        self._arrange_cards()

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
        note.setWordWrap(True)  # long captions wrap instead of widening the page
        box.addWidget(heading)
        box.addWidget(note)
        return card, box

    def _build_overview(self):
        page = QWidget()
        self.repo_box = QComboBox()
        self.repo_box.addItem(ALL_REPOS)
        self.repo_box.addItems(list(BURNDOWN_BY_REPO))
        self.repo_box.setToolTip("Show the reports for all repos or for one.")
        self.repo_box.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.repo_box.setMinimumContentsLength(24)
        self.repo_box.currentIndexChanged.connect(self._update)
        self.reset_btn = QPushButton("Reset to default")
        self.reset_btn.setObjectName("link")
        self.reset_btn.setCursor(Qt.PointingHandCursor)
        self.reset_btn.clicked.connect(lambda: self.repo_box.setCurrentIndex(0))
        filters = QHBoxLayout()
        filters.addWidget(self.repo_box)
        filters.addStretch()
        filters.addWidget(self.reset_btn)

        self.strip = QGridLayout()
        self.strip.setSpacing(12)
        self._kpi_cards = []
        self._kpi_columns = 0
        self.card_values = {}
        for name in ("Open", "Closed", "Total", "Cost per confirmed finding"):
            card = QFrame()
            card.setObjectName("card")
            box = QVBoxLayout(card)
            value = QLabel("n/a" if name.startswith("Cost") else "0")
            value.setObjectName("cardValue")
            box.addWidget(value)
            caption = QLabel(name)
            caption.setWordWrap(True)
            box.addWidget(caption)
            if name.startswith("Cost"):
                card.setToolTip("Needs real scan runs with token usage, so it is not available on sample data.")
            self.card_values[name] = value
            self._kpi_cards.append(card)

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
        layout.addLayout(self.strip)
        layout.addLayout(grid, 1)
        layout.addWidget(note)
        return page

    def _arrange_cards(self):
        """Four cards in a row when there is room, two rows of two when the window is narrow or zoomed."""
        columns = 4 if self.width() >= 1000 else 2
        if columns == self._kpi_columns:
            return
        self._kpi_columns = columns
        for card in self._kpi_cards:
            self.strip.removeWidget(card)
        for i, card in enumerate(self._kpi_cards):
            self.strip.addWidget(card, i // columns, i % columns)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._arrange_cards()

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
        self.title = title
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

    def set_embedded(self, embedded):
        """Inside the Findings page the breadcrumb and title belong to that page."""
        self.breadcrumb.setVisible(not embedded)
        self.title.setVisible(not embedded)

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


class FindingsPage(QWidget):
    """Findings: a board of every finding (latest scan of each repo) and the list of scan runs, as two tabs."""
    back_requested = pyqtSignal()
    finding_selected = pyqtSignal(int, str)  # index of the scan in the history, finding id
    ALL_SEVERITIES = "All severities"
    ALL_STATUSES = "All statuses"
    TABS = ("All findings", "Scan runs")
    COLUMNS = ("ID", "Severity", "Finding", "Repository", "Location", "Status")
    SORT_FIELDS = ("id", "severity", "title", "repo", "location", "status")

    def __init__(self, history_page):
        super().__init__()
        self._entries = []  # (history index, repo, finding)
        self._shown = []
        self._sort_field = None
        self._sort_order = Qt.AscendingOrder
        self.history_page = history_page
        self.history_page.set_embedded(True)

        self.breadcrumb = Breadcrumb("Home", "Findings")
        self.breadcrumb.back_clicked.connect(self.back_requested)
        title = QLabel("Findings")
        title.setObjectName("statsTitle")
        self.tabs = QTabBar()
        self.tabs.setDrawBase(False)
        self.tabs.setExpanding(False)
        for name in self.TABS:
            self.tabs.addTab(name)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_board())
        self.pages.addWidget(self.history_page)
        self.tabs.currentChanged.connect(self.pages.setCurrentIndex)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 24)
        layout.setSpacing(10)
        layout.addWidget(self.breadcrumb)
        layout.addWidget(title)
        layout.addWidget(self.tabs, 0, Qt.AlignLeft)
        layout.addWidget(self.pages, 1)

    def show_tab(self, index):
        self.tabs.setCurrentIndex(index)

    def _build_board(self):
        page = QWidget()
        strip = QHBoxLayout()
        strip.setSpacing(12)
        self.group_values = {}
        for group in STATUS_GROUPS:
            card = ClickableCard()
            card.setToolTip(f"Show only {group.lower()} findings")
            card.clicked.connect(lambda g=group: self.status_filter.setCurrentText(g))
            box = QVBoxLayout(card)
            value = QLabel("0")
            value.setObjectName("cardValue")
            box.addWidget(value)
            box.addWidget(QLabel(group))
            self.group_values[group] = value
            strip.addWidget(card)

        self.repo_filter = QComboBox()
        self.repo_filter.addItem(ALL_REPOS)
        self.severity_filter = QComboBox()
        self.severity_filter.addItem(self.ALL_SEVERITIES)
        self.severity_filter.addItems(SEVERITY_ORDER)
        self.status_filter = QComboBox()
        self.status_filter.addItem(self.ALL_STATUSES)
        self.status_filter.addItems(list(STATUS_GROUPS))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings")
        self.reset_btn = QPushButton("Reset to default")
        self.reset_btn.setObjectName("link")
        self.reset_btn.setCursor(Qt.PointingHandCursor)
        self.reset_btn.clicked.connect(self.reset_filters)
        for box in (self.repo_filter, self.severity_filter, self.status_filter):
            box.currentIndexChanged.connect(self._render)
        self.search.textChanged.connect(self._render)
        filters = QHBoxLayout()
        filters.setSpacing(10)
        for box in (self.repo_filter, self.severity_filter, self.status_filter):
            filters.addWidget(box)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.reset_btn)

        self.table = make_table(list(self.COLUMNS))
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 125)
        self.table.setColumnWidth(1, 105)
        self.table.setColumnWidth(3, 220)
        self.table.setColumnWidth(4, 250)
        self.table.setColumnWidth(5, 130)
        self.table.setItemDelegate(SeverityRowDelegate(self.table))
        header = self.table.horizontalHeader()
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._toggle_sort)
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._clear_sort)
        self.table.cellClicked.connect(self._choose)
        self.empty = QLabel("No findings match these filters.")
        self.empty.setObjectName("muted")
        self.empty.setAlignment(Qt.AlignCenter)
        note = QLabel("Sample data. Click a finding to open it in its scan. Click a column header to sort.")
        note.setObjectName("muted")

        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(12)
        layout.addLayout(strip)
        layout.addLayout(filters)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.empty)
        layout.addWidget(note)
        return page

    def refresh(self, history):
        """Rebuild from the scan history (newest first): the latest scan of each repo counts."""
        self._entries = [(index, history[index].repo, finding)
                         for index in latest_scan_indexes(history).values()
                         for finding in history[index].findings]
        current = self.repo_filter.currentText()
        self.repo_filter.blockSignals(True)
        self.repo_filter.clear()
        self.repo_filter.addItem(ALL_REPOS)
        self.repo_filter.addItems(list(latest_scan_indexes(history)))  # every repo, even with no findings
        index = self.repo_filter.findText(current)
        self.repo_filter.setCurrentIndex(index if index >= 0 else 0)
        self.repo_filter.blockSignals(False)
        self._render()

    def reset_filters(self):
        for box in (self.repo_filter, self.severity_filter, self.status_filter):
            box.setCurrentIndex(0)
        self.search.clear()

    def _toggle_sort(self, column):
        field = self.SORT_FIELDS[column]
        if self._sort_field == field:
            self._sort_order = Qt.DescendingOrder if self._sort_order == Qt.AscendingOrder else Qt.AscendingOrder
        else:
            self._sort_field, self._sort_order = field, Qt.AscendingOrder
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().setSortIndicator(column, self._sort_order)
        self._render()

    def _clear_sort(self, _position=None):
        self._sort_field = None
        self.table.horizontalHeader().setSortIndicatorShown(False)
        self._render()

    def _render(self, *_args):
        repo = self.repo_filter.currentText()
        severity = self.severity_filter.currentText()
        status = self.status_filter.currentText()
        text = self.search.text().strip().casefold()
        matching = []
        for entry in self._entries:
            _index, repo_name, f = entry
            if repo != ALL_REPOS and repo_name != repo:
                continue
            if severity != self.ALL_SEVERITIES and f.severity != severity:
                continue
            if text and text not in " ".join((f.id, f.title, f.location, f.cwe, repo_name)).casefold():
                continue
            matching.append(entry)
        for group, label in self.group_values.items():  # the counts ignore the status filter itself
            label.setText(str(sum(status_group(e[2].status) == group for e in matching)))
        shown = [e for e in matching if status == self.ALL_STATUSES or status_group(e[2].status) == status]
        field = self._sort_field or "severity"
        shown.sort(key=lambda e: finding_sort_key(e[2], field, e[1]),
                   reverse=self._sort_field is not None and self._sort_order == Qt.DescendingOrder)
        self._shown = shown

        self.table.setRowCount(len(shown))
        for row, (_index, repo_name, f) in enumerate(shown):
            colours = SEVERITY_COLORS.get(f.severity)
            for col, value in enumerate([f.id, f.severity, f.title, repo_name, f.location, f.status]):
                item = QTableWidgetItem(value)
                if colours:
                    item.setBackground(QColor(colours[0]))
                    item.setForeground(QColor(colours[1]))
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()
        self.empty.setVisible(not shown)

    def _choose(self, row, _column):
        if 0 <= row < len(self._shown):
            index, _repo, finding = self._shown[row]
            self.finding_selected.emit(index, finding.id)

    def showEvent(self, event):
        super().showEvent(event)
        self.table.resizeRowsToContents()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.table.resizeRowsToContents()


def apply_decision(finding, decision, reason, note):
    """Record a reviewer's Accept/Dispute decision on a finding. Mocked: nothing leaves the app."""
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


DISPUTES_KEY = "findings/disputes"


def load_disputes(settings):
    """{'repo|finding id': {'reason': ..., 'note': ...}} saved from earlier sessions."""
    try:
        data = json.loads(settings.value(DISPUTES_KEY, "{}", type=str) or "{}")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_dispute(settings, repo, finding):
    disputes = load_disputes(settings)
    disputes[f"{repo}|{finding.id}"] = {"reason": finding.reason, "note": finding.note}
    settings.setValue(DISPUTES_KEY, json.dumps(disputes))
    settings.sync()


def apply_disputes(settings, repo, findings):
    """Mark findings that were disputed in an earlier session (same repo and id)."""
    disputes = load_disputes(settings)
    for finding in findings:
        saved = disputes.get(f"{repo}|{finding.id}")
        if isinstance(saved, dict):
            apply_decision(finding, "Disputed", str(saved.get("reason", "")), str(saved.get("note", "")))


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


class FindingPanel(QFrame):
    """What opens under a clicked finding: the issue, where it is, the proposed fix, and the actions.

    Accept fix, Dispute and Verify are mocked: they change sample data only and never touch a repository.
    """
    changed = pyqtSignal()  # the finding's status or decision changed
    resized = pyqtSignal()  # the panel's height changed (a form opened, a note appeared)
    FIX_ACCEPTED_NOTE = ("Fix accepted (sample). A real run would write tests and open a pull request. "
                         "Nothing was changed.")
    VERIFIED_NOTE = "Verified (sample verdict: fixed). Mocked: nothing was actually checked."
    REASON_PROMPT = "Choose a reason"

    def __init__(self, finding):
        super().__init__()
        self.finding = finding
        self.setObjectName("findingPanel")
        colours = SEVERITY_COLORS.get(finding.severity)
        accent = colours[1] if colours else "#38BDF8"
        self.setStyleSheet(
            f"QFrame#findingPanel {{ background: #0F1C31; border-left: 3px solid {accent}; border-radius: 0; }}")

        self.heading = QLabel()
        self.heading.setStyleSheet("font-weight: 600;")
        self.cwe_link = QPushButton()
        self.cwe_link.setObjectName("link")
        self.cwe_link.setCursor(Qt.PointingHandCursor)
        self.cwe_link.clicked.connect(self._open_cwe)
        wrong, attacker = sample_issue(finding)
        self.wrong_text = self._body(wrong)
        self.attacker_text = self._body(attacker)
        self.location_label = self._body(finding.location)
        self.location_label.setObjectName("muted")

        self.code_view = QPlainTextEdit()
        self.code_view.setReadOnly(True)
        self.code_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.code_view.setStyleSheet("font-family: Consolas, 'Courier New', monospace;")
        self._show_code()
        self.fix_text = self._body(sample_fix(finding))
        self.decision_label = self._body("")
        self.decision_label.setObjectName("muted")
        self.action_note = self._body("")
        self.action_note.setObjectName("muted")
        self.action_note.hide()

        self.accept_btn = QPushButton("Accept fix")
        self.accept_btn.setObjectName("primary")
        self.dispute_btn = QPushButton("Dispute")
        self.verify_btn = QPushButton("Verify")
        self.accept_btn.setToolTip("Accept the proposed fix (mocked: shows what a real run would do).")
        self.dispute_btn.setToolTip("Dispute this finding: false positive, handled elsewhere, or the fix would "
                                    "break something. A reason is required.")
        self.accept_btn.clicked.connect(self._accept_fix)
        self.dispute_btn.clicked.connect(self._open_form)
        self.verify_btn.clicked.connect(self._verify)
        for btn in (self.accept_btn, self.dispute_btn, self.verify_btn):
            btn.setStyleSheet("padding: 8px 14px;")  # a widget's own stylesheet beats inherited ones
        actions = QHBoxLayout()
        actions.setSpacing(8)
        for btn in (self.accept_btn, self.dispute_btn, self.verify_btn):
            actions.addWidget(btn)
        actions.addStretch()

        # Inline dispute form: the reason is required, and "Other" needs a note.
        self.decision_form = QFrame()
        self.decision_form.hide()
        self.decision_title = QLabel()
        self.decision_title.setStyleSheet("font-weight: 600;")
        self.decision_reason = QComboBox()
        self.decision_note = QPlainTextEdit()
        self.decision_note.setPlaceholderText("Context (required for Other)")
        self.decision_note.setFixedHeight(70)
        self.decision_save = QPushButton("Save dispute")
        self.decision_save.setObjectName("primary")
        self.decision_cancel = QPushButton("Cancel")
        for btn in (self.decision_save, self.decision_cancel):
            btn.setStyleSheet("padding: 8px 14px;")
        self.decision_save.clicked.connect(self._save_dispute)
        self.decision_cancel.clicked.connect(self._close_form)
        self.decision_reason.currentIndexChanged.connect(self._validate_form)
        self.decision_note.textChanged.connect(self._validate_form)
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

        box = QVBoxLayout(self)
        box.setContentsMargins(18, 8, 18, 8)
        box.setSpacing(2)
        top = QHBoxLayout()
        top.addWidget(self.heading)
        top.addStretch()
        top.addWidget(self.cwe_link)
        box.addLayout(top)
        box.addWidget(self._section("What is wrong"))
        box.addWidget(self.wrong_text)
        box.addWidget(self._section("What an attacker can do"))
        box.addWidget(self.attacker_text)
        where = QHBoxLayout()
        where.setSpacing(10)
        where.addWidget(self._section("Where"))
        where.addWidget(self.location_label, 1)
        box.addLayout(where)
        box.addWidget(self.code_view)
        box.addWidget(self._section("Proposed fix (sample)"))
        box.addWidget(self.fix_text)
        box.addWidget(self.decision_label)
        box.addWidget(self.action_note)
        box.addSpacing(4)
        box.addLayout(actions)
        box.addWidget(self.decision_form)
        self.refresh()

    @staticmethod
    def _body(text):
        label = QLabel(text)
        label.setWordWrap(True)
        return label

    @staticmethod
    def _section(text):
        label = QLabel(text)
        label.setObjectName("muted")
        label.setStyleSheet("margin-top: 2px;")
        return label

    def _show_code(self):
        snippet = sample_snippet(self.finding)
        _path, flagged = split_location(self.finding.location)
        if not snippet:
            self.code_view.setPlainText("No sample code for this finding.")
            self.code_view.setFixedHeight(44)
            return
        lines = [f"{'>' if number == flagged else ' '} {number:>4} | {text}" for number, text in snippet]
        self.code_view.setPlainText("\n".join(lines))
        self.code_view.setFixedHeight(19 * len(lines) + 14)
        selections = []
        for index, (number, _text) in enumerate(snippet):
            if number == flagged:
                selection = QTextEdit.ExtraSelection()
                selection.format.setBackground(QColor("#3B2A12"))
                selection.format.setProperty(QTextFormat.FullWidthSelection, True)
                selection.cursor = QTextCursor(self.code_view.document().findBlockByNumber(index))
                selections.append(selection)
        self.code_view.setExtraSelections(selections)

    def refresh(self):
        finding = self.finding
        self.heading.setText(f"{finding.id}  |  {finding.severity}  |  {finding.status}")
        url = cwe_url(finding.cwe)
        self.cwe_link.setVisible(bool(url))
        if url:
            name = cwe_name(finding.cwe)
            self.cwe_link.setText(f"{finding.cwe} {name} ↗" if name else f"{finding.cwe} ↗")
            self.cwe_link.setToolTip(url)
        status = finding.status
        self.accept_btn.setEnabled(status not in ("Fix accepted", "Verified", "Merged", "Disputed"))
        self.dispute_btn.setEnabled(status not in ("Disputed", "Verified", "Merged"))
        can_verify = status in ("Fix accepted", "PR open", "Merged")
        self.verify_btn.setEnabled(can_verify)
        self.verify_btn.setToolTip("Check that the fix resolved the finding (mocked on sample data)." if can_verify
                                   else "Accept the fix first.")
        if finding.decision:
            text = f"{finding.decision}: {finding.reason}"
            if finding.note:
                text += f". Context: {finding.note}"
            self.decision_label.setText(text)
        self.decision_label.setVisible(bool(finding.decision))

    def _note(self, text):
        self.action_note.setText(text)
        self.action_note.setVisible(bool(text))

    def _done(self):
        self.refresh()
        self.changed.emit()
        self.resized.emit()

    def _accept_fix(self):
        self.finding.status = "Fix accepted"
        self._note(self.FIX_ACCEPTED_NOTE)
        self._done()

    def _verify(self):
        self.finding.status = "Verified"
        self._note(self.VERIFIED_NOTE)
        self._done()

    def _open_form(self):
        self.decision_title.setText(f"Dispute: {self.finding.id}")
        self.decision_reason.blockSignals(True)
        self.decision_reason.clear()
        self.decision_reason.addItem(self.REASON_PROMPT)
        self.decision_reason.model().item(0).setEnabled(False)
        self.decision_reason.addItems(DISPUTE_REASONS)
        self.decision_reason.setCurrentIndex(0)
        self.decision_reason.blockSignals(False)
        self.decision_note.clear()
        self._validate_form()
        self.decision_form.show()
        self.resized.emit()

    def _validate_form(self, *_args):
        reason = self.decision_reason.currentText()
        valid = self.decision_reason.currentIndex() > 0 and (
            reason != "Other" or bool(self.decision_note.toPlainText().strip()))
        self.decision_save.setEnabled(valid)

    def _save_dispute(self):
        if not self.decision_save.isEnabled():
            return
        apply_decision(self.finding, "Disputed", self.decision_reason.currentText(),
                       self.decision_note.toPlainText())
        self.decision_form.hide()
        self._note("")
        self._done()

    def _close_form(self):
        self.decision_form.hide()
        self.resized.emit()

    def _open_cwe(self):
        url = cwe_url(self.finding.cwe)
        if url:
            QDesktopServices.openUrl(QUrl(url))


class ScanPage(QWidget):
    finished = pyqtSignal(object)  # emits a ScanRecord
    repo_chart_requested = pyqtSignal(str)  # the small burndown was clicked: show the big one for this repo
    back_requested = pyqtSignal()
    finding_changed = pyqtSignal(str, object)  # repo, finding: a decision or status changed
    SIDE_WIDTH = 300
    SORT_FIELDS = ("id", "severity", "title", "location", "status")

    def __init__(self, sample_findings, sample_output):
        super().__init__()
        self.sample_findings = sample_findings
        self.sample_output = sample_output
        self._line_index = 0
        self._run_output = []
        self._findings = []  # as filled
        self._rows = []  # findings in table order
        self._expanded = None  # the finding whose details are open under its row
        self._detail_row = None  # table row holding the details
        self.panel = None
        self._sort_field = None  # None: worst severity first
        self._sort_order = Qt.AscendingOrder
        self._scan_repo = ""
        self.state_loader = None  # fn(repo, findings): marks findings disputed in earlier sessions
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._next_line)
        self.phrase_timer = QTimer(self)
        self.phrase_timer.timeout.connect(self._rotate_phrase)
        self.phrases = PhraseRotator()
        self.progress = None  # the scanning popup while a scan runs
        self._dim = None  # darkens the window behind it
        self._chart_repo = None
        self._phase = 0

        self.breadcrumb = Breadcrumb("Findings", "New scan")
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

        # Findings table: click a row to open its details underneath, click again to close.
        self.table = make_table(["ID", "Severity", "Finding", "Location", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 115)
        self.table.setColumnWidth(1, 105)
        self.table.setColumnWidth(3, 290)
        self.table.setColumnWidth(4, 125)
        self.table.setItemDelegate(SeverityRowDelegate(self.table))
        self.table.cellClicked.connect(self._on_row_clicked)
        header = self.table.horizontalHeader()
        header.setSectionsClickable(True)
        header.sectionClicked.connect(self._toggle_sort)
        header.setContextMenuPolicy(Qt.CustomContextMenu)
        header.customContextMenuRequested.connect(self._clear_sort)

        # Right column: severity counts and the repo burndown
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
        self.side = QWidget()
        self.side.setFixedWidth(self.SIDE_WIDTH)
        side_box = QVBoxLayout(self.side)
        side_box.setContentsMargins(0, 0, 0, 0)
        side_box.setSpacing(12)
        side_box.addWidget(self.tracker)
        side_box.addWidget(chart_card, 1)

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
        self._scan_repo = ""
        self.breadcrumb.set_current("New scan")

    def show_record(self, record):
        """Read-only view of a past scan."""
        self.timer.stop()
        self._close_progress()
        self.banner.hide()
        self.repo.setText(record.repo)
        self._scan_repo = record.repo
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
        self._resize_rows()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_rows()

    # The small per-repo burndown opens the big one on the Reports page
    def _set_repo_chart(self, repo):
        self._chart_repo = repo
        self.repo_chart.set_points(burndown_series(repo) if repo else [])

    def _open_repo_chart(self):
        if self._chart_repo:
            self.repo_chart_requested.emit(burndown_repo_key(self._chart_repo))

    # Finding details: open under the clicked row, close on a second click or a click on another finding
    def _finding_at(self, table_row):
        index = self._data_index(table_row)
        return self._rows[index] if index is not None else None

    def _data_index(self, table_row):
        """Index into self._rows for a table row, or None for the details row or a row past the end."""
        if self._detail_row is not None:
            if table_row == self._detail_row:
                return None
            if table_row > self._detail_row:
                table_row -= 1
        return table_row if 0 <= table_row < len(self._rows) else None

    def _on_row_clicked(self, row, _column):
        index = self._data_index(row)
        if index is None:
            return
        finding = self._rows[index]
        was_open = finding is self._expanded
        self._collapse()
        self.table.selectRow(index)
        if not was_open:
            self._expand(index)

    def select_finding(self, finding_id):
        """Select a finding by id and open its details (used when it is chosen on the Findings board)."""
        for index, finding in enumerate(self._rows):
            if finding.id == finding_id:
                self._collapse()
                self.table.selectRow(index)
                self._expand(index)
                return True
        return False

    def _expand(self, index):
        finding = self._rows[index]
        self.panel = FindingPanel(finding)
        self.panel.changed.connect(self._panel_changed)
        self.panel.resized.connect(self._panel_resized)
        row = index + 1
        self.table.insertRow(row)
        self.table.setSpan(row, 0, 1, self.table.columnCount())
        blocker = QTableWidgetItem()
        blocker.setFlags(Qt.NoItemFlags)  # the details row cannot be selected
        self.table.setItem(row, 0, blocker)
        self.table.setCellWidget(row, 0, self.panel)
        self._detail_row = row
        self._expanded = finding
        self._size_detail()
        # the clicked row goes to the top so the whole details panel is in view
        QTimer.singleShot(0, lambda: self._scroll_to(finding))  # after the view has updated its range

    def _scroll_to(self, finding):
        if finding is self._expanded and finding in self._rows:
            self.table.scrollToItem(self.table.item(self._rows.index(finding), 0), QAbstractItemView.PositionAtTop)

    def _collapse(self):
        if self._detail_row is None:
            return
        row = self._detail_row
        self.panel = None
        self._expanded = None
        self._detail_row = None
        self.table.removeCellWidget(row, 0)
        self.table.removeRow(row)

    def _size_detail(self):
        """Give the details row the height its content needs at the table's width."""
        if self._detail_row is None or self.panel is None:
            return
        self.panel.layout().activate()
        width = max(self.table.viewport().width(), 1)
        height = self.panel.heightForWidth(width) if self.panel.hasHeightForWidth() else 0
        self.table.setRowHeight(self._detail_row, max(height, self.panel.sizeHint().height()))

    def _panel_resized(self):
        """The panel grew (a form opened): resize its row, then keep its bottom edge in view."""
        self._size_detail()
        QTimer.singleShot(0, self._show_panel_bottom)

    def _show_panel_bottom(self):
        if self._detail_row is None:
            return
        bottom = self.table.rowViewportPosition(self._detail_row) + self.table.rowHeight(self._detail_row)
        overflow = bottom - self.table.viewport().height()
        if overflow > 0:
            bar = self.table.verticalScrollBar()
            bar.setValue(bar.value() + overflow)

    def _resize_rows(self):
        for row in range(self.table.rowCount()):
            if row != self._detail_row:
                self.table.resizeRowToContents(row)
        self._size_detail()

    def _panel_changed(self):
        finding = self._expanded
        if finding is None:
            return
        index = self._rows.index(finding)
        self.table.item(index, 4).setText(finding.status)
        self._size_detail()
        self.finding_changed.emit(self._scan_repo, finding)

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
        repo = self.repo.text().strip() or REPO_URL
        self._scan_repo = repo
        if self.state_loader is not None:
            self.state_loader(repo, findings)
        self._fill_table(findings)
        self._set_repo_chart(repo)
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
        self._collapse()
        self._findings = list(findings)
        self.tracker.update_counts(self._findings)
        self._render_rows()
        if self._rows:
            self.table.selectRow(0)

    def _sorted_findings(self):
        # A severity outside SEVERITY_ORDER sorts last instead of raising.
        if self._sort_field is None:
            return sorted(self._findings, key=lambda f: severity_rank(f.severity))
        rows = sorted(self._findings, key=lambda f: finding_sort_key(f, self._sort_field))
        return rows[::-1] if self._sort_order == Qt.DescendingOrder else rows

    def _render_rows(self):
        self._rows = self._sorted_findings()
        self.table.setRowCount(len(self._rows))
        for row, f in enumerate(self._rows):
            colours = SEVERITY_COLORS.get(f.severity)
            for col, value in enumerate([f.id, f.severity, f.title, f.location, f.status]):
                item = QTableWidgetItem(value)
                if colours:
                    item.setBackground(QColor(colours[0]))
                    item.setForeground(QColor(colours[1]))
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()

    def _resort(self):
        current = self._current_finding()
        self._collapse()
        self._render_rows()
        if current is not None and current in self._rows:
            self.table.selectRow(self._rows.index(current))

    def _toggle_sort(self, column):
        field = self.SORT_FIELDS[column]
        if self._sort_field == field:
            self._sort_order = Qt.DescendingOrder if self._sort_order == Qt.AscendingOrder else Qt.AscendingOrder
        else:
            self._sort_field, self._sort_order = field, Qt.AscendingOrder
        self.table.horizontalHeader().setSortIndicatorShown(True)
        self.table.horizontalHeader().setSortIndicator(column, self._sort_order)
        self._resort()

    def _clear_sort(self, _position=None):
        self._sort_field = None
        self.table.horizontalHeader().setSortIndicatorShown(False)
        self._resort()

    def _current_finding(self):
        rows = self.table.selectionModel().selectedRows()
        return self._finding_at(rows[0].row()) if rows else None


class MainWindow(QMainWindow):
    HOME, FINDINGS, SCAN, REPORTS = 0, 1, 2, 3
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
        for record in self.history:
            apply_disputes(self.app_settings, record.repo, record.findings)

        self.home_page = HomePage()
        self.history_page = HistoryPage()
        self.scan_page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
        self.reports_page = ReportsPage()
        self.findings_page = FindingsPage(self.history_page)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.findings_page)  # holds the scan runs list as its second tab
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.reports_page)
        self._page_history = [self.HOME]
        self._page_history_position = 0
        self.home_page.reports_requested.connect(self.show_reports)
        self.home_page.findings_requested.connect(self.show_findings)
        self._scan_origin = 1  # the Findings tab the scan page leads back to: 0 findings, 1 scan runs

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

        self.home_page.new_scan_requested.connect(self.new_scan)
        self.history_page.new_scan.connect(self.new_scan)
        self.scan_page.back_requested.connect(self._leave_scan)
        self.findings_page.back_requested.connect(self.show_home)
        self.findings_page.finding_selected.connect(self.open_finding)
        self.stack.currentChanged.connect(self._on_page_changed)
        self.reports_page.back_requested.connect(self.show_home)
        self.reports_page.new_scan_requested.connect(self.new_scan)
        self.home_page.getting_started_closed.connect(self._on_getting_started_closed)
        self.history_page.record_selected.connect(self.open_record)
        self.scan_page.finished.connect(self.add_record)
        self.scan_page.state_loader = lambda repo, findings: apply_disputes(self.app_settings, repo, findings)
        self.scan_page.finding_changed.connect(self._on_finding_changed)
        self.scan_page.repo_chart_requested.connect(self.show_repo_burndown)
        self.history_page.refresh(self.history)
        self._apply_zoom(self.DEFAULT_ZOOM)

    def show_home(self):
        self._navigate_to(self.HOME)

    def show_reports(self):
        self._navigate_to(self.REPORTS)

    def show_findings(self):
        self.findings_page.show_tab(0)
        self._navigate_to(self.FINDINGS)

    def _on_page_changed(self, index):
        if index == self.FINDINGS:  # decisions made in a scan show up on the board
            self.findings_page.refresh(self.history)

    def _set_scan_origin(self, tab):
        self._scan_origin = tab

    def _leave_scan(self):
        self.findings_page.show_tab(self._scan_origin)
        self._navigate_to(self.FINDINGS)

    def _on_finding_changed(self, repo, finding):
        if finding.decision == "Disputed":  # disputes are remembered between sessions
            save_dispute(self.app_settings, repo, finding)

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
        self.findings_page.show_tab(1)
        self._navigate_to(self.FINDINGS)

    def new_scan(self):
        self._set_scan_origin(1)
        self.scan_page.reset()
        self._navigate_to(self.SCAN)

    def open_record(self, row):
        self._set_scan_origin(1)
        self.scan_page.show_record(self.history[row])
        self._navigate_to(self.SCAN)

    def open_finding(self, row, finding_id):
        """Open the scan holding a finding chosen on the findings board, with its panel open."""
        self.scan_page.show_record(self.history[row])
        self._set_scan_origin(0)
        self._navigate_to(self.SCAN)
        self.scan_page.select_finding(finding_id)

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
