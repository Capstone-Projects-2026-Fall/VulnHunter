"""GUI tests on synthetic data: happy path, empty states, edge cases.

Run from the repo root:

    python -m pytest gui/tests/test_gui_synthetic.py -v   (from the repo root)

On a headless Linux machine, run with ``QT_QPA_PLATFORM=offscreen``.
No live scan, network, or Claude account is involved. These tests check that the
mock GUI behaves as designed; they do not test real VulnHunter output.
"""

from dataclasses import replace

import pytest
from PyQt5.QtCore import QEvent, QPoint, Qt
from PyQt5.QtGui import QKeyEvent
from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication, QLabel

from gui import main_gui as gui
from gui.main_gui import HistoryPage, MainWindow, ScanPage
from gui.data.mock_data import (
    DISABLED_MODELS, MODEL_IDS, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SAMPLE_SNIPPETS, SEED_HISTORY,
    SEVERITY_ORDER, Finding, code_url, sample_fix, sample_issue, sample_snippet, split_location,
)


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    """A MainWindow built without settings would use the real registry key; give it a temp file instead."""
    real = QSettings
    monkeypatch.setattr(gui, "QSettings", lambda *_args: real(str(tmp_path / "app.ini"), real.IniFormat))


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def run_demo_scan(page):
    """Drive the demo replay to completion without waiting on the timer."""
    page.start_scan()
    page.timer.stop()
    for _ in range(len(page._run_output) + 1):
        page._next_line()


def table_column(page, col):
    detail_row = getattr(page, "_detail_row", None)  # an open details row is not a finding
    return [page.table.item(r, col).text() for r in range(page.table.rowCount()) if r != detail_row]


# Happy path

def test_demo_scan_fills_table_and_emits_record(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    records = []
    page.finished.connect(records.append)

    run_demo_scan(page)

    assert page.table.rowCount() == len(SAMPLE_FINDINGS)
    assert len(records) == 1
    assert records[0].mode == "Demo"
    assert records[0].findings == list(SAMPLE_FINDINGS)
    assert page.scan_btn.isEnabled()


def test_demo_scan_log_names_the_selected_model(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.model_box.setCurrentText("DeepSeek")
    run_demo_scan(page)
    log = page.output.toPlainText()
    assert MODEL_IDS["DeepSeek"] in log
    assert "{model_id}" not in log


def test_finished_scan_is_added_to_history_and_can_be_reopened(qapp):
    window = MainWindow()
    before = len(window.history)

    run_demo_scan(window.scan_page)

    assert len(window.history) == before + 1
    assert window.history_page.table.rowCount() == before + 1
    window.open_record(0)
    assert window.stack.currentIndex() == window.SCAN
    assert not window.scan_page.scan_btn.isEnabled()  # past scans are read only
    assert window.scan_page.table.rowCount() == len(SAMPLE_FINDINGS)


def test_seed_history_is_shown_on_startup(qapp):
    window = MainWindow()
    assert window.history_page.table.rowCount() == len(SEED_HISTORY)


# Empty states

def test_new_scan_page_is_empty_with_nothing_open(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.reset()
    assert page.table.rowCount() == 0
    assert page.output.toPlainText() == ""
    assert page.panel is None and page._current_finding() is None


def test_empty_history_page(qapp):
    page = HistoryPage()
    page.refresh([])
    assert page.table.rowCount() == 0
    assert page.summary.text() == "0 scans · 0 findings · 0 verified"


def test_history_header_click_toggles_sort_and_right_click_clears(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    selected = []
    page.record_selected.connect(selected.append)
    header = page.table.horizontalHeader()

    header.sectionClicked.emit(3)
    assert table_column(page, 3) == [
        "Oct 18, 2026", "Oct 20, 2026", "Oct 23, 2026", "Oct 24, 2026"]
    assert header.sortIndicatorOrder() == Qt.AscendingOrder
    page.table.cellClicked.emit(0, 0)
    assert selected == [3]

    header.sectionClicked.emit(3)
    assert table_column(page, 3) == [
        "Oct 24, 2026", "Oct 23, 2026", "Oct 20, 2026", "Oct 18, 2026"]
    assert header.sortIndicatorOrder() == Qt.DescendingOrder

    header.sectionClicked.emit(3)
    assert table_column(page, 3) == [
        "Oct 18, 2026", "Oct 20, 2026", "Oct 23, 2026", "Oct 24, 2026"]
    assert header.sortIndicatorOrder() == Qt.AscendingOrder

    header.customContextMenuRequested.emit(QPoint(0, 0))
    assert table_column(page, 3) == [record.date for record in SEED_HISTORY]
    assert not header.isSortIndicatorShown()


def test_history_numeric_columns_sort_by_value(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)

    page.sort_by_column(4)

    assert table_column(page, 4) == ["0", "1", "7", "7"]


def test_scan_with_zero_findings(qapp):
    page = ScanPage([], SAMPLE_OUTPUT)
    run_demo_scan(page)
    assert page.table.rowCount() == 0
    assert all(label.text() == "0" for label in page.tracker.counts.values())


# Edge cases

def test_a_selection_alone_opens_nothing(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table(SAMPLE_FINDINGS)  # selects row 0
    assert page._current_finding() is not None and page.panel is None
    page.table.clearSelection()
    assert page._current_finding() is None


def test_long_text_and_many_rows(qapp):
    page = ScanPage([], [])
    findings = [
        Finding(f"VULN-{i:04d}", SEVERITY_ORDER[i % len(SEVERITY_ORDER)],
                "x" * 400, "src/" + "deep/" * 40 + "file.py:1", "Open")
        for i in range(300)
    ]
    page._fill_table(findings)
    assert page.table.rowCount() == 300
    severities = table_column(page, 1)
    assert severities == sorted(severities, key=SEVERITY_ORDER.index)


def test_blank_repo_in_demo_mode_still_scans(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.repo.setText("   ")
    records = []
    page.finished.connect(records.append)
    run_demo_scan(page)
    assert records and records[0].repo.strip()


# Not-implemented paths

def test_unchecking_demo_takes_live_route_and_shows_errors(qapp, monkeypatch):
    # The live route calls LLMConnector. Stub it so no real request is ever made.
    calls = []

    class FakeConnector:
        def __init__(self, model_name):
            calls.append(model_name)
            raise RuntimeError("stubbed: no network in tests")

    monkeypatch.setattr(gui, "LLMConnector", FakeConnector)
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.demo.setChecked(False)
    page.start_scan()

    assert calls == ["Claude Opus"]
    assert "stubbed: no network in tests" in page.output.toPlainText()
    assert page.table.rowCount() == 0  # no findings are produced on the live route yet
    assert not page.timer.isActive()


# Model dropdown

def test_model_dropdown_enabled_and_disabled_entries(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    model = page.model_box.model()
    enabled = [page.model_box.itemText(i) for i in range(page.model_box.count())
               if model.item(i).isEnabled()]
    disabled = [page.model_box.itemText(i) for i in range(page.model_box.count())
                if not model.item(i).isEnabled()]
    assert enabled == list(MODEL_IDS)
    assert len(disabled) == len(DISABLED_MODELS)
    assert all("not available yet" in name for name in disabled)


def test_model_dropdown_selection_can_change(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.model_box.setCurrentText("DeepSeek")
    assert page.model_box.currentText() == "DeepSeek"


# Navigation

def test_home_navigation(qapp):
    window = MainWindow()
    assert window.stack.currentIndex() == window.HOME
    assert window._page_history_position == 0

    window.home_page.new_scan_requested.emit()
    assert window.stack.currentIndex() == window.SCAN
    window.go_back()
    assert window.stack.currentIndex() == window.HOME

    window.home_page.findings_requested.emit()
    assert window.stack.currentIndex() == window.FINDINGS
    window.show_reports()
    assert window.stack.currentIndex() == window.REPORTS

    window.go_back()
    assert window.stack.currentIndex() == window.FINDINGS
    window.go_forward()
    assert window.stack.currentIndex() == window.REPORTS
    window.go_forward()  # nothing further
    assert window.stack.currentIndex() == window.REPORTS


def test_navigation_shortcuts_and_branching_history(qapp):
    window = MainWindow()
    window.show_history()
    window.show_reports()

    back_event = QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.ControlModifier)
    QApplication.sendEvent(window.home_button, back_event)
    assert window.stack.currentIndex() == window.FINDINGS

    command_forward_event = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Right, Qt.MetaModifier)
    QApplication.sendEvent(window.home_button, command_forward_event)
    assert window.stack.currentIndex() == window.REPORTS

    command_back_event = QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.MetaModifier)
    QApplication.sendEvent(window.home_button, command_back_event)
    assert window.stack.currentIndex() == window.FINDINGS

    forward_event = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Right, Qt.ControlModifier)
    QApplication.sendEvent(window.home_button, forward_event)
    assert window.stack.currentIndex() == window.REPORTS

    window.go_back()
    window.show_home()
    assert window.stack.currentIndex() == window.HOME
    assert window._page_history_position == len(window._page_history) - 1  # a new page drops "forward"


def test_default_window_size_fits_screen_but_not_below_minimum():
    min_w, min_h = gui.MIN_WINDOW_SIZE
    pref_w, pref_h = gui.PREFERRED_WINDOW_SIZE
    # Large screen: the preferred size.
    assert gui.default_window_size(2560, 1440) == (pref_w, pref_h)
    # Small screen: shrinks to fit, but never below the minimum.
    width, height = gui.default_window_size(1366, 768)
    assert min_w <= width <= pref_w and min_h <= height <= pref_h
    assert gui.default_window_size(800, 600) == (min_w, min_h)


def test_main_window_uses_minimum_size(qapp):
    window = MainWindow()
    assert (window.minimumWidth(), window.minimumHeight()) == gui.MIN_WINDOW_SIZE
    assert window.width() >= gui.MIN_WINDOW_SIZE[0]
    assert window.height() >= gui.MIN_WINDOW_SIZE[1]


def test_main_window_zoom_shortcuts_scale_contents_not_window(qapp):
    window = MainWindow()
    window.show()
    qapp.processEvents()
    initial_size = (window.width(), window.height())
    initial_column_width = window.scan_page.table.columnWidth(0)
    history_table = window.history_page.table
    initial_stylesheet = window.styleSheet()
    window.reset_zoom()
    qapp.processEvents()
    assert window.styleSheet() == initial_stylesheet
    home_title_font = window.home_button.font()
    home_title_metrics = (
        window.home_button.fontMetrics().height(),
        window.home_button.fontMetrics().horizontalAdvance(window.home_button.text()),
    )
    page_title = window.home_page.findChildren(QLabel)[0]
    font_heights = [
        (
            page_title.fontMetrics().height(),
            window.scan_page.repo.fontMetrics().height(),
            history_table.fontMetrics().height(),
        )
    ]

    window.zoom_in()
    assert window._zoom == pytest.approx(window.DEFAULT_ZOOM + window.ZOOM_STEP)
    qapp.processEvents()
    font_heights.append((
        page_title.fontMetrics().height(),
        window.scan_page.repo.fontMetrics().height(),
        history_table.fontMetrics().height(),
    ))
    assert all(new > old for old, new in zip(font_heights[-2], font_heights[-1]))
    window.reset_zoom()
    qapp.processEvents()
    font_heights = [(
        page_title.fontMetrics().height(),
        window.scan_page.repo.fontMetrics().height(),
        history_table.fontMetrics().height(),
    )]

    for _ in range(2):
        window.zoom_in()
        qapp.processEvents()
        font_heights.append((
            page_title.fontMetrics().height(),
            window.scan_page.repo.fontMetrics().height(),
            history_table.fontMetrics().height(),
        ))
    assert all(
        all(new > old for old, new in zip(previous, current))
        for previous, current in zip(font_heights, font_heights[1:])
    )

    max_steps = round((window.MAX_ZOOM - 1.2) / window.ZOOM_STEP)
    for _ in range(max_steps):
        window.zoom_in()
    assert (window.width(), window.height()) == initial_size
    assert window._zoom == window.MAX_ZOOM
    assert f"font-size: {round(18 * window._zoom)}px;" in window.styleSheet().split("QMainWindow")[0]
    qapp.processEvents()
    home_button = window.home_button
    assert f"QPushButton#home {{ font-size: {gui.HOME_BUTTON_PX}px; }}" in window.styleSheet()
    assert home_button.width() >= 260
    assert home_button.width() > home_button.fontMetrics().horizontalAdvance(home_button.text())
    assert home_button.height() >= 48
    assert (
        home_button.fontMetrics().height(),
        home_button.fontMetrics().horizontalAdvance(home_button.text()),
    ) == home_title_metrics
    assert window.scan_page.table.columnWidth(0) == initial_column_width
    assert window.scan_page.table.wordWrap()
    assert f"QTableWidget {{ font-size: {round(18 * window._zoom)}px; }}" in window.styleSheet()
    assert f"QHeaderView::section {{ font-size: {round(18 * window._zoom)}px; }}" in window.styleSheet()
    window.scan_page._fill_table(SAMPLE_FINDINGS)
    assert f"QTableWidget {{ font-size: {round(18 * window._zoom)}px; }}" in window.styleSheet()

    max_zoom_stylesheet = window.styleSheet()
    max_zoom_table_rule = f"QTableWidget {{ font-size: {round(18 * window._zoom)}px; }}"
    for _ in range(3):
        window.zoom_in()
    assert window.styleSheet() == max_zoom_stylesheet
    assert max_zoom_table_rule in window.styleSheet()

    min_steps = round((window.MAX_ZOOM - window.MIN_ZOOM) / window.ZOOM_STEP)
    for _ in range(min_steps):
        window.zoom_out()
    assert window._zoom == window.MIN_ZOOM
    min_zoom_stylesheet = window.styleSheet()
    for _ in range(3):
        window.zoom_out()
    assert window.styleSheet() == min_zoom_stylesheet

    window.reset_zoom()
    assert window._zoom == window.DEFAULT_ZOOM
    assert window.styleSheet() == initial_stylesheet
    assert (window.width(), window.height()) == initial_size
    assert window.scan_page.table.columnWidth(0) == initial_column_width
    assert (
        home_button.fontMetrics().height(),
        home_button.fontMetrics().horizontalAdvance(home_button.text()),
    ) == home_title_metrics
    window.close()


def test_zoom_shortcut_accepts_key_repeat(qapp):
    window = MainWindow()
    repeated_plus = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Plus, Qt.ControlModifier, "+", True
    )

    assert window._handle_zoom_shortcut(repeated_plus)
    assert window._zoom == window.DEFAULT_ZOOM + window.ZOOM_STEP

    repeated_minus = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Minus, Qt.MetaModifier, "-", True
    )
    assert window._handle_zoom_shortcut(repeated_minus)
    assert window._zoom == window.DEFAULT_ZOOM
    window.close()


def test_base_font_size_is_larger_than_original():
    # Stakeholder asked for larger text than the original 14px.
    assert "font-size: 18px" in gui.STYLE.split("QMainWindow")[0]


def test_main_window_defines_show_reports_once():
    # Guards against a duplicate definition.
    import inspect
    source = inspect.getsource(gui.MainWindow)
    assert source.count("def show_reports") == 1
    assert "show_stats" not in source


# Demo usage figures

def test_demo_scan_shows_no_usage_figures(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    records = []
    page.finished.connect(records.append)
    run_demo_scan(page)
    assert (records[0].tokens, records[0].duration) == ("n/a", "n/a")


# Home page text size

def test_home_page_text_is_larger_than_the_base_font():
    assert "#homeHeading { font-size: 44px" in gui.HOME_QSS
    assert "#cardTitle { font-size: 24px" in gui.HOME_QSS


def test_home_page_widgets_use_the_sized_object_names(qapp):
    home = gui.HomePage()
    assert home.objectName() == "homePage"
    assert home.findChild(gui.QLabel, "homeHeading") is not None
    assert home.findChild(gui.QLabel, "homeSub") is not None
    assert home.findChild(gui.QPushButton, "homeNewScan") is not None


# Findings open under their row; Accept fix, Dispute and Verify (all mocked)

def scan_with_findings(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    run_demo_scan(page)
    return page


def select_finding(page, finding_id):
    row = next(i for i, f in enumerate(page._rows) if f.id == finding_id)
    page.table.selectRow(row)
    return page._current_finding()


def open_finding(page, finding_id):
    """Click a finding's row and return the details panel that opens under it."""
    index = next(i for i, f in enumerate(page._rows) if f.id == finding_id)
    row = index + 1 if page._detail_row is not None and index >= page._detail_row else index
    page._on_row_clicked(row, 0)  # rows under an open details row sit one lower in the table
    return page.panel


def dispute(panel, reason_index=1, note=""):
    """Click Dispute, fill the inline form and save it."""
    panel.dispute_btn.click()
    panel.decision_reason.setCurrentIndex(reason_index)
    panel.decision_note.setPlainText(note)
    panel.decision_save.click()


def test_details_open_under_the_clicked_row(qapp):
    page = scan_with_findings(qapp)
    rows = page.table.rowCount()
    panel = open_finding(page, "VULN-005")
    finding = panel.finding
    index = page._rows.index(finding)

    assert page.table.rowCount() == rows + 1 and page._detail_row == index + 1
    assert page.table.cellWidget(index + 1, 0) is panel
    heading = panel.heading.text()
    assert finding.id in heading and finding.severity in heading and finding.status in heading
    assert panel.wrong_text.text() == sample_issue(finding)[0]
    assert panel.attacker_text.text() == sample_issue(finding)[1]
    assert panel.location_label.text() == finding.location
    assert panel.fix_text.text() == sample_fix(finding)  # the fix is shown at once, no Fix button
    assert panel.cwe_link.text() == f"{finding.cwe} {gui.cwe_name(finding.cwe)} ↗"
    assert not hasattr(panel, "fix_btn") and not hasattr(panel, "report_btn")


def test_clicking_again_or_clicking_another_finding_closes_it(qapp):
    page = scan_with_findings(qapp)
    rows = page.table.rowCount()
    first = open_finding(page, "VULN-005")
    assert first is page.panel and page._expanded.id == "VULN-005"

    open_finding(page, "VULN-005")  # the same row again
    assert page.panel is None and page.table.rowCount() == rows

    open_finding(page, "VULN-005")
    second = open_finding(page, "VULN-006")  # a different row: only one is ever open
    assert page.table.rowCount() == rows + 1
    assert page._expanded.id == "VULN-006" and second is page.panel
    assert page._current_finding().id == "VULN-006"


def test_the_details_row_is_not_a_finding(qapp):
    page = scan_with_findings(qapp)
    open_finding(page, "VULN-005")
    detail_row = page._detail_row
    before = page._expanded
    page._on_row_clicked(detail_row, 0)  # a click inside the details does nothing to the row
    assert page._expanded is before and page._detail_row == detail_row
    assert page._data_index(detail_row) is None
    assert page._finding_at(detail_row + 1) is page._rows[detail_row]


def test_a_scan_finishing_does_not_open_the_details_by_itself(qapp):
    page = scan_with_findings(qapp)
    assert page._current_finding() is not None  # the first row is selected
    assert page.panel is None


def test_a_real_click_on_a_row_opens_and_closes_the_details(qapp):
    from PyQt5.QtTest import QTest
    window = MainWindow()
    window.resize(1360, 900)
    window.show()
    window.new_scan()
    page = window.scan_page
    run_demo_scan(page)
    qapp.processEvents()
    rect = page.table.visualItemRect(page.table.item(2, 2))
    QTest.mouseClick(page.table.viewport(), Qt.LeftButton, pos=rect.center())
    qapp.processEvents()
    assert page.panel is not None and page._expanded is page._rows[2]
    rect = page.table.visualItemRect(page.table.item(2, 2))  # the view may have scrolled
    QTest.mouseClick(page.table.viewport(), Qt.LeftButton, pos=rect.center())
    qapp.processEvents()
    assert page.panel is None
    window.close()


def test_the_details_row_gets_the_height_it_needs(qapp):
    window = MainWindow()
    window.resize(1360, 900)
    window.show()
    window.new_scan()
    page = window.scan_page
    run_demo_scan(page)
    open_finding(page, "VULN-005")
    qapp.processEvents()
    assert page.table.rowHeight(page._detail_row) >= page.panel.sizeHint().height() > 150
    before = page.table.rowHeight(page._detail_row)
    page.panel.dispute_btn.click()  # the inline form makes it taller
    assert page.table.rowHeight(page._detail_row) > before
    window.close()


def test_accept_fix_then_verify(qapp):
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-005")
    finding = panel.finding
    assert not panel.verify_btn.isEnabled() and panel.verify_btn.toolTip() == "Accept the fix first."

    panel.accept_btn.click()
    assert finding.status == "Fix accepted"
    assert table_column(page, 4)[page._rows.index(finding)] == "Fix accepted"
    assert not panel.accept_btn.isEnabled() and panel.verify_btn.isEnabled()
    assert "Nothing was changed" in panel.action_note.text()
    assert gui.status_group(finding.status) == "In progress"

    panel.verify_btn.click()
    assert finding.status == "Verified" and not panel.verify_btn.isEnabled()
    assert "Mocked" in panel.action_note.text()
    assert table_column(page, 4)[page._rows.index(finding)] == "Verified"


def test_dispute_needs_a_reason_and_other_needs_a_note(qapp):
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-005")
    panel.dispute_btn.click()
    assert not panel.decision_form.isHidden()
    assert panel.decision_reason.currentText() == "Choose a reason"
    assert not panel.decision_save.isEnabled()

    panel.decision_reason.setCurrentIndex(1)
    assert panel.decision_save.isEnabled()
    other = panel.decision_reason.findText("Other")
    panel.decision_reason.setCurrentIndex(other)
    assert not panel.decision_save.isEnabled()  # "Other" needs context
    panel.decision_note.setPlainText("   ")
    assert not panel.decision_save.isEnabled()
    panel.decision_note.setPlainText("Owned by another team")
    assert panel.decision_save.isEnabled()
    assert [panel.decision_reason.itemText(i) for i in range(1, panel.decision_reason.count())] == gui.DISPUTE_REASONS


def test_dispute_records_reason_and_context(qapp):
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-006")
    finding = panel.finding
    dispute(panel, reason_index=1, note="  Test code only  ")

    assert (finding.decision, finding.status) == ("Disputed", "Disputed")
    assert finding.reason == gui.DISPUTE_REASONS[0] and finding.note == "Test code only"
    assert table_column(page, 4)[page._rows.index(finding)] == "Disputed"
    assert "Disputed: False positive" in panel.decision_label.text()
    assert "Test code only" in panel.decision_label.text()
    assert panel.decision_form.isHidden() and not panel.dispute_btn.isEnabled()


def test_cancelled_dispute_changes_nothing(qapp):
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-005")
    finding = panel.finding
    before = finding.status
    panel.dispute_btn.click()
    panel.decision_reason.setCurrentIndex(2)
    panel.decision_note.setPlainText("should not be saved")
    panel.decision_cancel.click()
    assert panel.decision_form.isHidden()
    assert finding.status == before and (finding.decision, finding.reason, finding.note) == ("", "", "")


def test_changes_never_touch_the_sample_data_or_other_scans(qapp):
    originals = [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS]
    window = MainWindow()
    run_demo_scan(window.scan_page)
    dispute(open_finding(window.scan_page, "VULN-005"))

    assert [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS] == originals
    seeded = [f for r in window.history[1:] for f in r.findings if f.id == "VULN-005"]
    assert seeded and all(f.decision == "" for f in seeded)


def test_a_dispute_is_remembered_across_sessions_and_scans(qapp, tmp_path):
    ini = str(tmp_path / "remember.ini")
    first = MainWindow(settings=QSettings(ini, QSettings.IniFormat))
    run_demo_scan(first.scan_page)
    panel = open_finding(first.scan_page, "VULN-005")
    dispute(panel, reason_index=3, note="Would break the cluster")
    accepted = open_finding(first.scan_page, "VULN-006")
    accepted.accept_btn.click()  # workflow steps are session state, not remembered

    second = MainWindow(settings=QSettings(ini, QSettings.IniFormat))
    run_demo_scan(second.scan_page)  # the same repo again
    again = select_finding(second.scan_page, "VULN-005")
    assert (again.decision, again.status) == ("Disputed", "Disputed")
    assert again.reason == gui.DISPUTE_REASONS[2] and again.note == "Would break the cluster"
    assert select_finding(second.scan_page, "VULN-006").status != "Fix accepted"
    assert gui.load_disputes(QSettings(ini, QSettings.IniFormat)).keys() == {
        f"{gui.repo_name(gui.REPO_URL)}|VULN-005"}


def test_disputes_ignore_damaged_saved_data(qapp, tmp_path):
    settings = QSettings(str(tmp_path / "bad.ini"), QSettings.IniFormat)
    settings.setValue(gui.DISPUTES_KEY, "{not json")
    assert gui.load_disputes(settings) == {}
    settings.setValue(gui.DISPUTES_KEY, "[1, 2]")
    assert gui.load_disputes(settings) == {}
    findings = [replace(f) for f in SAMPLE_FINDINGS]
    gui.apply_disputes(settings, "any", findings)
    assert all(f.decision == "" for f in findings)


def test_a_dispute_is_kept_when_a_past_scan_is_reopened(qapp):
    window = MainWindow()
    run_demo_scan(window.scan_page)
    dispute(open_finding(window.scan_page, "VULN-005"), note="kept")

    window.open_record(1)  # some other scan
    window.open_record(0)  # back to the one just decided on
    finding = select_finding(window.scan_page, "VULN-005")
    assert finding.decision == "Disputed" and finding.note == "kept"


def test_code_view_shows_a_sample_snippet_with_the_flagged_line(qapp):
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-003")
    _path, line = split_location(panel.finding.location)
    assert f"> {line:>4} |" in panel.code_view.toPlainText()
    assert code_url(panel.finding).endswith(f"#L{line}")
    assert panel.code_view.isReadOnly() and len(panel.code_view.extraSelections()) == 1


def test_cwe_link_opens_the_mitre_page(qapp, monkeypatch):
    opened = []
    monkeypatch.setattr(gui.QDesktopServices, "openUrl", lambda url: opened.append(url.toString()))
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-005")
    panel.cwe_link.click()
    assert opened == [gui.cwe_url(panel.finding.cwe)] and opened[0].startswith("https://cwe.mitre.org/")


def test_sample_issue_text_exists_for_every_sample_weakness():
    from gui.data.mock_data import DEFAULT_SAMPLE_ISSUE, sample_issue
    seeded = [f for r in SEED_HISTORY for f in r.findings]
    for finding in list(SAMPLE_FINDINGS) + seeded:
        wrong, attacker = sample_issue(finding)
        assert wrong and attacker
    assert sample_issue(Finding("X", "Low", "t", "a.py:1", "Open", cwe="CWE-1")) == DEFAULT_SAMPLE_ISSUE


def test_every_sample_finding_has_a_snippet_matching_its_line():
    seeded = [f for r in SEED_HISTORY for f in r.findings]
    for finding in list(SAMPLE_FINDINGS) + seeded:
        rows = sample_snippet(finding)
        assert rows, finding.id
        _path, line = split_location(finding.location)
        assert line in [n for n, _ in rows], finding.id
    assert set(SAMPLE_SNIPPETS) >= {f.id for f in SAMPLE_FINDINGS}


def test_split_location_and_code_url():
    assert split_location("src/a.py:12") == ("src/a.py", 12)
    assert split_location("src/a.py") == ("src/a.py", 0)
    finding = Finding("X", "Low", "t", "src/a.py:12", "Open")
    assert code_url(finding).endswith("/blob/main/src/a.py#L12")
    assert code_url(replace(finding, location="src/a.py")).endswith("/blob/main/src/a.py")


# UI cleanup: header, status pill, gear popup, reminder

def test_header_has_sample_tag_status_pill_and_help_but_no_gear(qapp):
    window = MainWindow()
    assert window.sample_tag.text() == "Sample data"
    assert window.status_pill.state() == "off"
    assert window.help_button.toolTip() == "Getting started"
    assert not hasattr(window, "gear_button")
    assert window.stack.count() == 4  # home, findings (with scan runs), scan, reports; API settings are a popover


def test_status_pill_pulses_only_while_not_connected(qapp):
    pill = gui.StatusPill()
    assert (pill.state(), pill.label_text()) == ("off", "API not connected")
    assert pill.is_pulsing()
    pill.set_state("ok")
    assert (pill.label_text(), pill.is_pulsing()) == ("Connected", False)
    pill.set_state("error")
    assert (pill.label_text(), pill.is_pulsing()) == ("Key rejected", False)
    pill.set_state("off")
    assert pill.is_pulsing()


def test_pill_follows_the_connector(qapp):
    window = MainWindow()
    window.connector_page.connected.emit("deepseek", "DeepSeek")
    assert window.status_pill.label_text() == "Connected"
    assert "DeepSeek" in window.status_pill.toolTip()

    window.connector_page.disconnected.emit()
    assert window.status_pill.state() == "off"

    window.connector_page.connect_failed.emit("401 unauthorized")
    assert window.status_pill.label_text() == "Key rejected"

    # Clearing the key after a rejection goes back to "not connected".
    window.connector_page.api_key.setText("sk-example")
    assert window.status_pill.state() == "error"
    window.connector_page.api_key.setText("")
    assert window.status_pill.state() == "off"


def test_failed_connect_emits_connect_failed(qapp):
    from gui.api_conn_page import ApiConnectorPage
    page = ApiConnectorPage()
    failures = []
    page.connect_failed.connect(failures.append)
    page._on_connect_done(False, "bad key")
    assert failures == ["bad key"]
    page._on_connect_done(True, "Model: x")
    assert failures == ["bad key"]


def test_clicking_the_status_pill_toggles_the_api_popover(qapp):
    window = MainWindow(QSettings())
    window.status_pill.clicked.emit()
    popover = window.api_popover
    assert popover.isVisible() and popover.isAncestorOf(window.connector_page)
    assert popover.width() == gui.ApiPopover.CARD_WIDTH
    assert window.connector_page.title_label.isHidden()  # compact: no big title
    window.status_pill.clicked.emit()
    assert not popover.isVisible()
    window.status_pill.clicked.emit()
    assert popover.isVisible()
    popover.close()


def test_api_popover_closes_on_an_outside_click_but_not_inside(qapp):
    from PyQt5.QtGui import QMouseEvent
    window = MainWindow(QSettings())
    window.show()
    window.status_pill.clicked.emit()
    popover = window.api_popover

    def press(global_point):
        local = QPoint(0, 0)
        return QMouseEvent(QEvent.MouseButtonPress, local, global_point, Qt.LeftButton,
                           Qt.LeftButton, Qt.NoModifier)

    window._close_popover_on_outside_click(press(popover.frameGeometry().center()))
    assert popover.isVisible()
    pill = window.status_pill
    window._close_popover_on_outside_click(press(pill.mapToGlobal(pill.rect().center())))
    assert popover.isVisible()  # the pill toggles it instead
    window._close_popover_on_outside_click(press(window.mapToGlobal(QPoint(5, window.height() - 5))))
    assert not popover.isVisible()
    window.close()


def test_escape_closes_the_api_popover(qapp):
    window = MainWindow(QSettings())
    window.status_pill.clicked.emit()
    popover = window.api_popover
    popover.keyPressEvent(QKeyEvent(QEvent.KeyPress, Qt.Key_Escape, Qt.NoModifier))
    assert not popover.isVisible()


def test_status_pill_is_a_clickable_label_with_hover_hints(qapp):
    window = MainWindow()
    pill = window.status_pill
    assert pill.cursor().shape() == Qt.PointingHandCursor
    assert pill.toolTip() == "Click to enter your API key"

    window.connector_page.connected.emit("deepseek", "DeepSeek")
    assert pill.toolTip() == "Connected to DeepSeek. Click to configure API key"
    window.connector_page.connect_failed.emit("401")
    assert pill.toolTip() == "The key was rejected: 401. Click to configure API key"
    window.connector_page.disconnected.emit()
    assert pill.toolTip() == "Click to enter your API key"


def test_real_mouse_click_on_the_pill_emits_clicked(qapp):
    from PyQt5.QtTest import QTest
    pill = gui.StatusPill()
    pill.resize(220, 36)
    pill.show()
    got = []
    pill.clicked.connect(lambda: got.append(1))
    QTest.mouseClick(pill, Qt.LeftButton)
    assert got == [1]
    QTest.mouseClick(pill, Qt.RightButton)  # only the left button counts
    assert got == [1]
    pill.close()


def test_pill_marks_hover_for_styling(qapp):
    from PyQt5.QtCore import QEvent
    pill = gui.StatusPill()
    pill.event(QEvent(QEvent.Enter))
    assert pill.property("hover") is True
    pill.event(QEvent(QEvent.Leave))
    assert pill.property("hover") is False


def test_getting_started_banner_respects_dont_show_again(qapp, tmp_path):
    settings = QSettings(str(tmp_path / "vulngui.ini"), QSettings.IniFormat)
    window = MainWindow(settings=settings)
    banner = window.home_page.getting_started
    assert len(banner.STEPS) == 3
    assert not gui.reminder_hidden(settings)

    assert window.maybe_show_reminder() is True
    assert not banner.isHidden()
    banner.close_btn.click()  # closed without ticking the box: it will show again
    assert banner.isHidden() and not gui.reminder_hidden(settings)

    assert window.maybe_show_reminder() is True
    banner.dont_show.setChecked(True)
    banner.close_btn.click()
    assert gui.reminder_hidden(settings)
    assert window.maybe_show_reminder() is False
    assert banner.isHidden()


def test_banner_follows_the_saved_choice_only_when_asked(qapp, tmp_path):
    window = MainWindow(settings=QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat))
    assert window.maybe_show_reminder() is True


# Home page

def test_home_page_greeting_and_new_scan_above_the_cards(qapp):
    home = gui.HomePage()
    heading = home.findChild(gui.QLabel, "homeHeading")
    assert heading.text() == "Welcome back, dev"
    cards = home.findChildren(gui.ModuleCard)
    assert [c.findChild(gui.QLabel, "cardTitle").text() for c in cards] == ["Findings", "Reports"]

    home.resize(1200, 800)
    home.show()
    qapp.processEvents()
    assert home.new_scan_btn.geometry().bottom() < min(c.geometry().top() for c in cards)
    home.close()


def test_home_page_has_no_api_card_or_dashboard(qapp):
    home = gui.HomePage()
    texts = {label.text() for label in home.findChildren(gui.QLabel)}
    assert "API Connector" not in texts and "Dashboard" not in texts
    assert "Stats" not in texts


def test_home_buttons_emit_their_signals(qapp):
    home = gui.HomePage()
    got = []
    home.new_scan_requested.connect(lambda: got.append("new"))
    home.findings_requested.connect(lambda: got.append("findings"))
    home.reports_requested.connect(lambda: got.append("reports"))
    home.new_scan_btn.click()
    for card in home.findChildren(gui.ModuleCard):
        card.click()
    assert got == ["new", "findings", "reports"]


# Scan History

def test_history_page_is_titled_scan_history(qapp):
    page = HistoryPage()
    assert "Scan History" in {label.text() for label in page.findChildren(gui.QLabel)}


def test_history_filters_narrow_the_list_and_the_cards(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    assert page.table.rowCount() == len(SEED_HISTORY)

    page.repo_filter.setCurrentText("sample-org/sample-backend")
    assert page.table.rowCount() == 2
    assert page.summary.text().startswith("2 scans")

    page.model_filter.setCurrentText("DeepSeek")
    assert page.table.rowCount() == 1
    assert table_column(page, 1) == ["DeepSeek"]

    page.model_filter.setCurrentIndex(0)
    page.repo_filter.setCurrentIndex(0)
    page.search.setText("payments")
    assert table_column(page, 0) == ["sample-org/payments-api"]
    page.search.setText("")
    assert page.table.rowCount() == len(SEED_HISTORY)


def test_filtered_and_sorted_rows_still_open_the_right_scan(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    selected = []
    page.record_selected.connect(selected.append)
    page.repo_filter.setCurrentText("sample-org/payments-api")
    page.table.cellClicked.emit(0, 0)
    assert SEED_HISTORY[selected[0]].repo == "sample-org/payments-api"


def test_history_filters_keep_their_choice_when_a_scan_is_added(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    page.model_filter.setCurrentText("DeepSeek")
    page.refresh(list(SEED_HISTORY) + [replace(SEED_HISTORY[0], model="DeepSeek")])
    assert page.model_filter.currentText() == "DeepSeek"
    assert page.table.rowCount() == 2


# Stats: aggregate burndown with a repo filter

def test_reports_page_shows_the_aggregate_then_one_repo(qapp):
    from gui.data.mock_data import BURNDOWN_BY_REPO, burndown_series, burndown_totals
    reports = gui.ReportsPage()
    assert reports.repo_box.itemText(0) == "All repos"
    open_now, closed, total = burndown_totals(burndown_series())
    assert [reports.card_values[k].text() for k in ("Open", "Closed", "Total")] == [
        str(open_now), str(closed), str(total)]
    assert [v for _, v in reports.chart.points] == [
        sum(week) for week in zip(*BURNDOWN_BY_REPO.values())]

    reports.repo_box.setCurrentText("sample-org/payments-api")
    assert [v for _, v in reports.chart.points] == BURNDOWN_BY_REPO["sample-org/payments-api"]
    assert reports.card_values["Total"].text() == "1"
    reports.chart.resize(900, 400)
    assert not reports.chart.grab().isNull()


def test_reports_tabs_cost_card_and_severity_bars(qapp):
    from gui.data.mock_data import open_by_severity, sample_repo_findings
    reports = gui.ReportsPage()
    assert [reports.tabs.tabText(i) for i in range(reports.tabs.count())] == ["Overview", "Providers", "Quality"]
    assert reports.card_values["Cost per confirmed finding"].text() == "n/a"
    counts = open_by_severity(sample_repo_findings())
    for tier in gui.SEVERITY_ORDER:
        assert reports.severity_values[tier].text() == str(counts.get(tier, 0))
        assert reports.severity_bars[tier].isHidden() == (tier not in counts)
    reports.repo_box.setCurrentText("sample-org/payments-api")
    assert all(v.text() == "0" for v in reports.severity_values.values())
    for index in (1, 2):
        reports.tabs.setCurrentIndex(index)
        assert reports.pages.currentIndex() == index


def test_providers_empty_state_starts_a_comparison(qapp):
    reports = gui.ReportsPage()
    got = []
    reports.new_scan_requested.connect(lambda: got.append(1))
    reports.providers_button.click()
    assert got == [1]


def test_open_by_severity_and_cwe_helpers():
    from gui.data.mock_data import cwe_name, cwe_url, open_by_severity, sample_repo_findings
    assert cwe_url("CWE-78") == "https://cwe.mitre.org/data/definitions/78.html"
    assert cwe_url("nonsense") == "" and cwe_url("") == ""
    assert cwe_name("CWE-78") == "OS command injection" and cwe_name("CWE-1") == ""
    assert open_by_severity(sample_repo_findings()) == {"High": 3, "Low": 2}
    assert open_by_severity(sample_repo_findings("sample-org/payments-api")) == {}


def test_only_the_scan_page_has_a_breadcrumb(qapp):
    window = MainWindow(QSettings())
    assert not hasattr(window.findings_page, "breadcrumb") and not hasattr(window.reports_page, "breadcrumb")
    assert not hasattr(window.history_page, "breadcrumb")

    window.show_reports()
    window.home_button.click()  # the logo is the way home
    assert window.stack.currentIndex() == window.HOME

    window.open_record(0)  # from the Scan runs tab
    assert window.scan_page.breadcrumb.current.text() == window.history[0].repo
    assert window.scan_page.breadcrumb.back_btn.text() == "← Findings"
    window.scan_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.FINDINGS
    assert window.findings_page.tabs.currentIndex() == 1
    window.new_scan()
    assert window.scan_page.breadcrumb.current.text() == "New scan"


def test_all_repos_burndown_is_the_sum_of_the_repos():
    from gui.data.mock_data import BURNDOWN_BY_REPO, burndown_series
    total = [v for _, v in burndown_series()]
    for week, value in enumerate(total):
        assert value == sum(series[week] for series in BURNDOWN_BY_REPO.values())
    assert burndown_series("not a sample repo") == burndown_series("sample-org/sample-backend")


def test_burndown_chart_handles_edge_data(qapp):
    for compact in (False, True):
        for points in ([], [("Week 1", 0)], [("Week 1", 3)], [("A", 40), ("B", 0)]):
            chart = gui.BurndownChart(points, compact=compact)
            chart.resize(600, 300)
            assert not chart.grab().isNull()


# Scan view: per-repo chart and collapsible log

def test_scan_page_shows_a_repo_burndown_after_a_scan(qapp):
    from gui.data.mock_data import burndown_series
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    assert page.repo_chart.points == []
    run_demo_scan(page)
    assert page.repo_chart.points == burndown_series("sample-org/sample-backend")
    page.reset()
    assert page.repo_chart.points == []


def test_opening_a_past_scan_shows_that_repos_burndown(qapp):
    from gui.data.mock_data import burndown_series
    window = MainWindow()
    row = next(i for i, r in enumerate(window.history) if r.repo == "sample-org/payments-api")
    window.open_record(row)
    assert window.scan_page.repo_chart.points == burndown_series("sample-org/payments-api")


def test_scan_log_is_collapsed_until_asked_for(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    assert page.output.isHidden() and "▸" in page.log_toggle.text()
    page.log_toggle.click()
    assert not page.output.isHidden() and "▾" in page.log_toggle.text()
    page.log_toggle.click()
    assert page.output.isHidden() and "▸" in page.log_toggle.text()


# Scanning popup, loading phrases and result card

def test_scan_opens_a_popup_that_follows_the_phases(qapp):
    from gui.data.mock_data import SCAN_PHRASES
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.start_scan()
    page.timer.stop()
    popup = page.progress
    assert popup is not None and popup.isVisible()
    assert popup.phase_index == 0
    assert popup.phrase_label.text() == SCAN_PHRASES[0][0] == "Detecting..."

    seen = []
    for _ in range(len(page._run_output)):
        page._next_line()
        if page.progress is not None:
            seen.append(page.progress.phase_index)
    assert 1 in seen and 2 in seen  # hunt, then verification
    assert seen[-1] == 3  # report
    assert popup.phrase_label.text() in SCAN_PHRASES[3]

    page._next_line()  # the run is over
    assert page.progress is None and not page.phrase_timer.isActive()


def test_cancelling_the_popup_stops_the_replay(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.start_scan()
    popup = page.progress
    popup.cancel_btn.click()
    assert page.progress is None
    assert not page.timer.isActive() and not page.phrase_timer.isActive()
    assert page.table.rowCount() == 0
    assert page.output.toPlainText() == "Scan cancelled."
    assert page.scan_btn.isEnabled()
    assert page.banner.isHidden()


def test_finishing_a_scan_shows_a_red_result_banner(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    run_demo_scan(page)
    banner = page.banner
    assert not banner.isHidden() and banner.level == "high"
    text = banner.label.text()
    assert "7 vulnerabilities detected" in text and "3 High, 4 Low" in text and "sample results" in text
    banner.close_btn.click()
    assert banner.isHidden()
    page.reset()
    assert banner.isHidden()


def test_result_banner_levels_and_wording(qapp):
    def banner(findings):
        widget = gui.ResultBanner()
        widget.show_findings(findings)
        return widget

    none = banner([])
    assert none.level == "none" and "No vulnerabilities found" in none.label.text()

    low_only = banner([Finding("A", "Low", "t", "a.py:1", "Open"), Finding("B", "Medium", "t", "a.py:2", "Open")])
    assert low_only.level == "other"
    assert "2 vulnerabilities detected" in low_only.label.text()

    one = banner([Finding("A", "High+", "t", "a.py:1", "Open")])
    assert one.level == "high" and "1 vulnerability detected" in one.label.text()


def test_phase_of_line_follows_the_sample_log_and_never_goes_back(qapp):
    from gui.data.mock_data import phase_of_line
    phase, phases = 0, []
    for line in SAMPLE_OUTPUT:
        phase = phase_of_line(line, phase)
        phases.append(phase)
    assert phases == sorted(phases)
    assert set(phases) == {0, 1, 2, 3}
    assert phase_of_line("[phase 1] late line", 3) == 3
    assert phase_of_line("", 2) == 2


def test_phrase_rotator_uses_only_approved_phrases_and_cycles(qapp):
    import random
    from gui.data.mock_data import HUNT_PHASE, SCAN_PHRASES
    rotator = gui.PhraseRotator(random.Random(0))
    assert rotator.next(0) == "Detecting..."
    hunt = [rotator.next(HUNT_PHASE) for _ in SCAN_PHRASES[HUNT_PHASE]]
    assert sorted(hunt) == sorted(SCAN_PHRASES[HUNT_PHASE])  # each phrase once per cycle
    assert rotator.next(HUNT_PHASE) in SCAN_PHRASES[HUNT_PHASE]  # then it refills
    assert [rotator.next(3), rotator.next(3)] == SCAN_PHRASES[3]
    assert all(p.endswith("...") for phrases in SCAN_PHRASES for p in phrases)


def test_progress_popup_rotates_its_phrase_on_the_timer(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.start_scan()
    page.timer.stop()
    before = page.progress.phrase_label.text()
    page._rotate_phrase()
    after = page.progress.phrase_label.text()
    assert after != before
    page.reset()
    assert page.progress is None


# Radar spinner, popups at the bottom, calmer style

def test_radar_spinner_turns_only_while_visible(qapp):
    spinner = gui.RadarSpinner()
    assert not spinner.is_spinning()
    spinner.show()
    assert spinner.is_spinning()
    before = spinner._angle
    spinner._tick()
    assert spinner._angle != before
    assert not spinner.grab().isNull()
    spinner.hide()
    assert not spinner.is_spinning()


def test_scanning_popup_has_no_title_and_no_sliding_bar(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.start_scan()
    page.timer.stop()
    texts = {label.text() for label in page.progress.findChildren(gui.QLabel)}
    assert "Scanning for vulnerabilities" not in texts
    assert isinstance(page.progress.spinner, gui.RadarSpinner)
    assert not hasattr(gui, "BusyBar")
    page.reset()


def test_scanning_screen_is_centred_and_dims_the_window(qapp):
    window = MainWindow(QSettings())
    window.resize(1360, 900)
    window.show()
    qapp.processEvents()
    window.new_scan()
    page = window.scan_page
    page.start_scan()
    page.timer.stop()
    qapp.processEvents()
    win = window.geometry()

    box = page.progress.frameGeometry()
    assert abs(box.center().x() - win.center().x()) <= 3
    assert abs(box.center().y() - win.center().y()) <= 3
    assert page.progress.width() >= 520 and page.progress.spinner.width() >= 160
    assert page._dim is not None and page._dim.geometry() == window.rect()

    for _ in range(len(page._run_output) + 1):
        page._next_line()
    qapp.processEvents()
    assert page._dim is None  # the scanning dim is gone
    assert not page.banner.isHidden()  # the result is inline, not another popup
    window.close()


def test_cancelling_removes_the_dim_overlay(qapp):
    window = MainWindow()
    window.show()
    window.new_scan()
    page = window.scan_page
    page.start_scan()
    assert page._dim is not None
    page.progress.cancel_btn.click()
    assert page._dim is None
    window.close()


def test_severity_panel_text_is_one_size():
    for name in ("severityHeading", "severityHeadline", "severityDetail"):
        assert f"QLabel#{name} {{ font-size: 16px" in gui.STYLE


def test_log_text_is_readable_and_monospace():
    block = gui.STYLE.split("QPlainTextEdit {")[1].split("}")[0]
    assert "font-size: 15px" in block and "Consolas" in block


def test_app_uses_one_clean_font_family():
    assert "Segoe UI" in gui.STYLE.split("QMainWindow")[0]


def test_equal_rows_get_equal_heights_once_the_page_is_shown(qapp):
    window = MainWindow()
    window.resize(1360, 900)
    window.show()
    window.show_history()
    qapp.processEvents()
    table = window.history_page.table
    # The first two seeded scans have the same repository name, so they should be the same height.
    assert table.rowHeight(0) == table.rowHeight(1)
    window.close()


# Severity colours, logo button, help button

def test_rows_are_coloured_by_severity_across_every_cell(qapp):
    from PyQt5.QtGui import QColor
    page = ScanPage([], [])
    findings = [Finding(f"V-{i}", tier, "title", "a.py:1", "Open")
                for i, tier in enumerate(["Low", "High+", "Informational", "High", "Medium"])]
    page._fill_table(findings)
    assert table_column(page, 1) == ["High+", "High", "Medium", "Low", "Informational"]
    for row, tier in enumerate(table_column(page, 1)):
        background, text = gui.SEVERITY_COLORS[tier]
        for col in range(page.table.columnCount()):
            item = page.table.item(row, col)
            assert item.background().color() == QColor(background)
            assert item.foreground().color() == QColor(text)


def test_severity_colour_scheme_matches_the_request(qapp):
    colours = gui.SEVERITY_COLORS
    assert list(colours) == ["High+", "High", "Medium", "Low", "Informational"]
    assert len({bg for bg, _ in colours.values()}) == 5  # every tier is distinct
    for tier, (background, text) in colours.items():
        assert background.startswith("#") and text.startswith("#")
    # dark red, red, orange, yellow: the red channel leads for the first two, green rises for the next
    from PyQt5.QtGui import QColor
    hp, h = QColor(colours["High+"][1]), QColor(colours["High"][1])
    m, low = QColor(colours["Medium"][1]), QColor(colours["Low"][1])
    assert hp.red() > hp.green() and h.red() > h.green()
    assert m.green() > h.green() and low.green() > m.green()


def test_unknown_severity_row_keeps_the_default_look(qapp):
    page = ScanPage([], [])
    page._fill_table([Finding("V-1", "Critical", "t", "a.py:1", "Open")])
    assert page.table.item(0, 1).background().style() == Qt.NoBrush


def test_selected_row_keeps_its_colour_and_paints_with_the_delegate(qapp):
    from PyQt5.QtGui import QColor
    page = ScanPage([], [])
    assert isinstance(page.table.itemDelegate(), gui.SeverityRowDelegate)
    page._fill_table([Finding("V-1", "High", "t", "a.py:1", "Open"),
                      Finding("V-2", "Low", "t", "a.py:2", "Open")])
    page.table.selectRow(0)
    assert page.table.item(0, 0).background().color() == QColor(gui.SEVERITY_COLORS["High"][0])
    page.table.resize(900, 300)
    assert not page.table.grab().isNull()


def test_status_change_keeps_the_row_colour(qapp):
    from PyQt5.QtGui import QColor
    page = scan_with_findings(qapp)
    panel = open_finding(page, "VULN-005")
    panel.accept_btn.click()
    row = page._rows.index(panel.finding)
    assert page.table.item(row, 4).text() == "Fix accepted"
    assert page.table.item(row, 4).background().color() == QColor(gui.SEVERITY_COLORS["High"][0])


def test_tracker_counts_use_the_tier_colours(qapp):
    tracker = gui.SeverityTracker()
    for tier, label in tracker.counts.items():
        assert gui.SEVERITY_COLORS[tier][1].lower() in label.styleSheet().lower()


def test_logo_button_text_is_larger(qapp):
    assert gui.HOME_BUTTON_PX == 28
    block = gui.STYLE.split("QPushButton#home {")[1].split("}")[0]
    assert f"font-size: {gui.HOME_BUTTON_PX}px" in block
    window = MainWindow()
    assert window.home_button.minimumHeight() >= 52


def test_help_button_reopens_getting_started_even_when_it_was_turned_off(qapp, tmp_path):
    settings = QSettings(str(tmp_path / "vulngui.ini"), QSettings.IniFormat)
    gui.set_reminder_hidden(settings, True)
    window = MainWindow(settings=settings)
    assert window.maybe_show_reminder() is False  # the launch banner stays off
    banner = window.home_page.getting_started
    assert banner.isHidden()

    window.show_history()
    window.help_button.click()
    assert window.stack.currentIndex() == window.HOME
    assert not banner.isHidden()
    assert banner.dont_show.isChecked()  # shows the saved choice

    banner.dont_show.setChecked(False)  # turn the launch banner back on
    banner.close_btn.click()
    assert not gui.reminder_hidden(settings)
    assert window.maybe_show_reminder() is True


# Green sonar scope

def test_sonar_scope_is_green_not_red(qapp):
    spinner = gui.RadarSpinner(size=170)
    spinner._angle = 300.0
    image = spinner.grab().toImage()
    green = red = 0
    for x in range(0, image.width(), 2):
        for y in range(0, image.height(), 2):
            c = image.pixelColor(x, y)
            if c.alpha() < 200:
                continue
            if c.green() > c.red() + 60 and c.green() > c.blue() + 20:
                green += 1
            if c.red() > c.green() + 60 and c.red() > c.blue() + 60:
                red += 1
    assert green > 40  # the arm, trail and blips
    assert red == 0  # the old red dots are gone


def test_blips_light_up_when_swept_then_fade(qapp):
    alpha = gui.RadarSpinner.blip_alpha
    assert alpha(0) == 255
    assert alpha(0) > alpha(90) > alpha(180) > alpha(197)
    assert alpha(200) == alpha(359) == int(255 * 0.12)
    assert alpha(360) == 255  # a full turn later it is swept again


def test_sonar_scope_turns_once_every_three_seconds(qapp):
    spinner = gui.RadarSpinner()
    frames_per_turn = 360 / spinner.SWEEP_STEP
    assert frames_per_turn * 25 == 3000  # 25ms frames
    start = spinner._angle
    for _ in range(int(frames_per_turn)):
        spinner._tick()
    assert abs((spinner._angle - start) % 360) < 1e-6


def test_sonar_scope_paints_at_every_size(qapp):
    for size in (48, 96, 170):
        assert not gui.RadarSpinner(size=size).grab().isNull()


# High+ is a deeper red than High

def test_high_plus_text_is_a_deeper_red_than_high(qapp):
    from PyQt5.QtGui import QColor
    high_plus = QColor(gui.SEVERITY_COLORS["High+"][1])
    high = QColor(gui.SEVERITY_COLORS["High"][1])
    assert high_plus.lightness() < high.lightness()
    assert high_plus.red() > high_plus.green() and high.red() > high.green()
    tracker = gui.SeverityTracker()
    assert gui.SEVERITY_COLORS["High+"][1].lower() in tracker.counts["High+"].styleSheet().lower()
    assert gui.SEVERITY_COLORS["High"][1].lower() in tracker.counts["High"].styleSheet().lower()
    # the zero counts too, not only the non-zero ones
    assert tracker.counts["High+"].text() == "0"


# The small burndown opens the big one

def test_clicking_the_small_chart_opens_the_big_one_for_that_repo(qapp):
    window = MainWindow()
    window.new_scan()
    page = window.scan_page
    run_demo_scan(page)
    page.banner.close_btn.click()
    assert window.stack.currentIndex() == window.SCAN

    page.repo_chart_card.clicked.emit()
    assert window.stack.currentIndex() == window.REPORTS
    assert window.reports_page.repo_box.currentText() == "sample-org/sample-backend"
    assert [v for _, v in window.reports_page.chart.points] == [7, 7, 6, 6, 5, 5]
    window.go_back()
    assert window.stack.currentIndex() == window.SCAN  # the scan page is still there


def test_the_small_chart_opens_the_repo_of_an_opened_past_scan(qapp):
    window = MainWindow()
    row = next(i for i, r in enumerate(window.history) if r.repo == "sample-org/payments-api")
    window.open_record(row)
    window.scan_page.repo_chart_card.clicked.emit()
    assert window.reports_page.repo_box.currentText() == "sample-org/payments-api"


def test_the_small_chart_does_nothing_before_a_scan(qapp):
    window = MainWindow()
    window.new_scan()
    window.scan_page.repo_chart_card.clicked.emit()
    assert window.stack.currentIndex() == window.SCAN


def test_clickable_card_is_a_button_like_card(qapp):
    from PyQt5.QtCore import QEvent
    from PyQt5.QtTest import QTest
    card = gui.ClickableCard()
    card.resize(120, 80)
    card.show()
    assert card.cursor().shape() == Qt.PointingHandCursor
    got = []
    card.clicked.connect(lambda: got.append(1))
    QTest.mouseClick(card, Qt.LeftButton)
    QTest.mouseClick(card, Qt.RightButton)
    assert got == [1]
    card.event(QEvent(QEvent.Enter))
    assert card.property("hover") is True
    card.event(QEvent(QEvent.Leave))
    assert card.property("hover") is False
    card.close()


def test_burndown_repo_key_falls_back_to_the_sample_repo():
    from gui.data.mock_data import burndown_repo_key
    assert burndown_repo_key("sample-org/payments-api") == "sample-org/payments-api"
    assert burndown_repo_key("github.com/anything") == "sample-org/sample-backend"


# Findings board, tabs and Dispute

def test_dispute_replaces_ignore_everywhere(qapp):
    panel = gui.FindingPanel(replace(SAMPLE_FINDINGS[0]))
    assert panel.dispute_btn.text() == "Dispute" and not hasattr(panel, "ignore_btn")
    assert "Handled elsewhere in the stack" in gui.DISPUTE_REASONS
    assert "Fix would break the system" in gui.DISPUTE_REASONS
    assert not hasattr(gui, "IGNORE_REASONS") and not hasattr(gui, "ACCEPT_REASONS")
    assert "Dispute" in gui.GettingStartedBanner.STEPS[2] and "Accept" in gui.GettingStartedBanner.STEPS[2]


def test_status_groups_cover_every_sample_status():
    from gui.data.mock_data import STATUS_GROUPS, status_group
    assert [status_group(s) for s in ("Open", "Fix proposed", "PR open", "Fix accepted", "Disputed", "Verified", "Merged")] == [
        "Open", "In progress", "In progress", "In progress", "Disputed", "Done", "Done"]
    assert status_group("something new") == "Open"
    assert list(STATUS_GROUPS) == ["Open", "In progress", "Disputed", "Done"]


def test_sort_keys_order_severity_location_and_status():
    from gui.data.mock_data import finding_sort_key, severity_rank, status_rank
    a = Finding("VULN-002", "Low", "b", "b/file.py:10", "Verified")
    b = Finding("VULN-010", "High+", "a", "a/file.py:9", "Open")
    c = Finding("VULN-003", "High", "c", "a/file.py:100", "Disputed")
    by = lambda field: [f.id for f in sorted([a, b, c], key=lambda f: finding_sort_key(f, field))]
    assert by("severity") == ["VULN-010", "VULN-003", "VULN-002"]  # High+ first, not alphabetical
    assert by("location") == ["VULN-010", "VULN-003", "VULN-002"]  # path, then line as a number
    assert by("status") == ["VULN-010", "VULN-003", "VULN-002"]  # open, disputed, done
    assert by("id") == ["VULN-002", "VULN-003", "VULN-010"]  # VULN-10 after VULN-3
    assert severity_rank("nonsense") > severity_rank("Informational")
    assert status_rank("nonsense") > status_rank("Merged")
    try:
        finding_sort_key(a, "colour")
    except ValueError:
        pass
    else:
        raise AssertionError("an unknown field should raise")


def test_scan_table_sorts_by_header_click(qapp):
    page = scan_with_findings(qapp)
    header = page.table.horizontalHeader()
    default = [f.id for f in page._rows]
    assert [f.severity for f in page._rows] == sorted((f.severity for f in page._rows), key=gui.SEVERITY_ORDER.index)

    page._toggle_sort(3)  # Location, ascending
    locations = [f.location for f in page._rows]
    keys = [split_location(loc) for loc in locations]
    assert keys == sorted(keys, key=lambda k: (k[0].casefold(), k[1]))
    assert header.isSortIndicatorShown() and header.sortIndicatorSection() == 3
    assert table_column(page, 3) == locations  # the table shows the sorted rows

    page._toggle_sort(3)  # again: descending
    assert page._sort_order == Qt.DescendingOrder and page._rows[0].location == max(
        locations, key=lambda l: (split_location(l)[0].casefold(), split_location(l)[1]))

    page._toggle_sort(4)  # Status
    from gui.data.mock_data import status_rank
    assert [status_rank(f.status) for f in page._rows] == sorted(status_rank(f.status) for f in page._rows)

    page._clear_sort()
    assert [f.id for f in page._rows] == default and not header.isSortIndicatorShown()


def test_sorting_closes_the_details_and_keeps_the_selection(qapp):
    page = scan_with_findings(qapp)
    open_finding(page, "VULN-005")
    page._toggle_sort(0)
    assert page.panel is None and page.table.rowCount() == len(SAMPLE_FINDINGS)
    assert page._current_finding().id == "VULN-005"


def test_board_lists_the_latest_scan_of_each_repo(qapp):
    from gui.data.mock_data import latest_scan_indexes
    window = MainWindow(QSettings())
    page = window.findings_page
    page.refresh(window.history)
    latest = latest_scan_indexes(window.history)
    expected = sum(len(window.history[i].findings) for i in latest.values())
    assert page.table.rowCount() == expected == 8
    assert page.repo_filter.count() == 1 + len(latest)
    counts = {name: int(chip.text().rsplit(" ", 1)[1]) for name, chip in page.chips.items()}
    assert counts["All"] == expected
    assert sum(v for name, v in counts.items() if name != "All") == expected
    severities = [page.table.item(r, 1).text() for r in range(page.table.rowCount())]
    assert severities == sorted(severities, key=gui.SEVERITY_ORDER.index)
    assert [page.table.horizontalHeaderItem(c).text() for c in range(page.table.columnCount())] == [
        "ID", "Severity", "Finding", "Repository", "Location", "Status"]


def test_board_sorts_by_header_click(qapp):
    window = MainWindow(QSettings())
    page = window.findings_page
    page.refresh(window.history)
    page._toggle_sort(4)  # Location
    paths = [page.table.item(r, 4).text() for r in range(page.table.rowCount())]
    keys = [(split_location(p)[0].casefold(), split_location(p)[1]) for p in paths]
    assert keys == sorted(keys)
    page._toggle_sort(4)
    paths = [page.table.item(r, 4).text() for r in range(page.table.rowCount())]
    keys = [(split_location(p)[0].casefold(), split_location(p)[1]) for p in paths]
    assert keys == sorted(keys, reverse=True)
    page._clear_sort()
    assert not page.table.horizontalHeader().isSortIndicatorShown()


def test_board_filters_and_chips_narrow_the_list(qapp):
    window = MainWindow(QSettings())
    page = window.findings_page
    page.refresh(window.history)
    total = page.table.rowCount()

    page.severity_filter.setCurrentText("Low")
    assert 0 < page.table.rowCount() < total
    assert all(page.table.item(r, 1).text() == "Low" for r in range(page.table.rowCount()))
    assert page.chips["All"].text() == f"All {page.table.rowCount()}"  # the counts follow the other filters
    page.severity_filter.setCurrentIndex(0)
    assert page.table.rowCount() == total

    page.repo_filter.setCurrentText("sample-org/payments-api")
    assert {page.table.item(r, 3).text() for r in range(page.table.rowCount())} == {"sample-org/payments-api"}
    page.repo_filter.setCurrentIndex(0)

    page.chips["Open"].click()
    assert page._status == "Open" and page.chips["Open"].isChecked() and not page.chips["All"].isChecked()
    assert all(gui.status_group(f.status) == "Open" for _i, _r, f in page._shown)
    page.search.setText("no such finding anywhere")
    assert page.table.rowCount() == 0 and not page.empty.isHidden()
    page.search.clear()
    page.chips["All"].click()
    assert page.empty.isHidden() and page._status is None and page.chips["All"].isChecked()
    assert not hasattr(page, "reset_btn")


def test_findings_page_has_two_tabs_and_holds_the_scan_runs(qapp):
    window = MainWindow(QSettings())
    page = window.findings_page
    assert [page.tabs.tabText(i) for i in range(page.tabs.count())] == ["All findings", "Scan runs"]
    assert page.pages.widget(1) is window.history_page
    assert window.history_page.title.isHidden()
    window.show_history()
    assert window.stack.currentIndex() == window.FINDINGS and page.tabs.currentIndex() == 1
    window.show_findings()
    assert page.tabs.currentIndex() == 0
    window.home_page.findings_requested.emit()
    assert window.stack.currentIndex() == window.FINDINGS

    window.show_history()  # New scan sits beside the tabs and works from either one
    page.new_scan_btn.click()
    assert window.stack.currentIndex() == window.SCAN


def test_choosing_a_finding_opens_its_scan_with_the_details_open(qapp):
    window = MainWindow(QSettings())
    window.show_findings()
    page = window.findings_page
    row = next(r for r, (_i, _repo, f) in enumerate(page._shown) if f.id == "VULN-005")
    page._choose(row, 0)

    assert window.stack.currentIndex() == window.SCAN
    assert window.scan_page._expanded.id == "VULN-005" and window.scan_page.panel is not None
    window.scan_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.FINDINGS and page.tabs.currentIndex() == 0


def test_a_dispute_shows_up_on_the_board(qapp):
    window = MainWindow(QSettings())
    window.show_findings()
    board = window.findings_page
    row = next(r for r, (_i, _repo, f) in enumerate(board._shown) if f.status == "Open")
    board._choose(row, 0)
    panel = window.scan_page.panel
    finding = panel.finding
    dispute(panel, reason_index=3, note="Would break the cluster")
    assert (finding.status, finding.reason) == ("Disputed", "Fix would break the system")

    window.show_findings()
    board = window.findings_page
    assert board.chips["Disputed"].text() == "Disputed 1"
    board.chips["Disputed"].click()
    assert board.table.rowCount() == 1 and board.table.item(0, 5).text() == "Disputed"


def test_the_eye_in_the_api_key_field_shows_and_hides_the_key(qapp):
    from gui.api_conn_page import ApiConnectorPage
    from PyQt5.QtWidgets import QLineEdit
    page = ApiConnectorPage()
    assert page.api_key.echoMode() == QLineEdit.Password
    assert page.show_key.isCheckable() and page.show_key.toolTip() == "Show the key"
    page.show_key.trigger()
    assert page.api_key.echoMode() == QLineEdit.Normal and page.show_key.toolTip() == "Hide the key"
    page.show_key.trigger()
    assert page.api_key.echoMode() == QLineEdit.Password
    assert not page.show_key.icon().isNull()


def test_reports_cards_wrap_when_the_window_is_narrow(qapp):
    reports = gui.ReportsPage()
    reports.resize(700, 800)
    reports._arrange_cards()
    assert {reports.strip.getItemPosition(i)[0] for i in range(4)} == {0, 1}  # two rows of two
    assert reports.minimumSizeHint().width() < 1000  # nothing forces the page wide
    reports.resize(1300, 800)
    reports._arrange_cards()
    assert {reports.strip.getItemPosition(i)[0] for i in range(4)} == {0}  # one row of four


def test_report_tabs_have_room_for_their_labels(qapp):
    assert "padding: 8px 16px" in gui.STYLE.split("QTabBar::tab {")[1].split("}")[0]
    assert "font-weight" not in gui.STYLE.split("QTabBar::tab {")[1].split("}")[0]


def test_pressing_the_action_buttons_does_not_jump_to_the_bottom(qapp):
    window = MainWindow()
    window.resize(1360, 900)
    window.show()
    window.new_scan()
    page = window.scan_page
    run_demo_scan(page)
    qapp.processEvents()
    assert page.table.verticalScrollMode() == gui.QAbstractItemView.ScrollPerPixel
    panel = open_finding(page, "VULN-005")
    qapp.processEvents()
    bar = page.table.verticalScrollBar()
    for button in (panel.accept_btn, panel.verify_btn, panel.dispute_btn):
        button.click()
        qapp.processEvents()
        # moves by at most a few lines, never to the end of the table
        assert bar.value() < bar.maximum() - 100
        assert page.table.rowViewportPosition(page._rows.index(panel.finding)) > -page.table.rowHeight(0)
    window.close()


# One clean header, one toolbar, and deleting a scan

def test_header_has_no_arrow_buttons_but_the_shortcuts_still_work(qapp):
    window = MainWindow()
    assert not hasattr(window, "back_button") and not hasattr(window, "forward_button")
    assert window.sample_tag.text() == "Sample data" and window.home_button.text() == "VulnHunter"
    window.show_findings()
    QApplication.sendEvent(window.home_button, QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.ControlModifier))
    assert window.stack.currentIndex() == window.HOME


def test_repo_names_ignore_the_github_prefix():
    from gui.data.mock_data import repo_name
    assert repo_name("https://github.com/sample-org/sample-backend") == "sample-org/sample-backend"
    assert repo_name("http://www.github.com/org/name.git/") == "org/name"
    assert repo_name("github.com/org/name") == "org/name"
    assert repo_name("sample-org/sample-backend") == "sample-org/sample-backend"
    assert repo_name("C:\\code\\my repo") == "C:\\code\\my repo" and repo_name("") == ""


def test_a_scan_of_a_github_url_is_stored_under_the_short_name(qapp):
    window = MainWindow(QSettings())
    run_demo_scan(window.scan_page)  # blank repo means the sample URL
    assert window.history[0].repo == "sample-org/sample-backend"
    window.findings_page.refresh(window.history)
    repos = [window.findings_page.table.item(r, 3).text() for r in range(window.findings_page.table.rowCount())]
    assert "https://github.com/sample-org/sample-backend" not in repos
    assert window.findings_page.repo_filter.findText("sample-org/sample-backend") >= 0
    assert window.findings_page.repo_filter.count() == len({r.repo for r in window.history}) + 1


def test_old_disputes_saved_under_a_full_url_still_apply(qapp, tmp_path):
    settings = QSettings(str(tmp_path / "old.ini"), QSettings.IniFormat)
    settings.setValue(gui.DISPUTES_KEY, '{"https://github.com/sample-org/sample-backend|VULN-005": '
                                        '{"reason": "False positive", "note": "old"}}')
    findings = [replace(f) for f in SAMPLE_FINDINGS]
    gui.apply_disputes(settings, "sample-org/sample-backend", findings)
    hit = next(f for f in findings if f.id == "VULN-005")
    assert (hit.status, hit.reason, hit.note) == ("Disputed", "False positive", "old")


def test_the_scan_runs_toolbar_puts_search_first_then_filters(qapp):
    page = HistoryPage()
    toolbar = page.layout().itemAt(0).layout()
    order = [toolbar.itemAt(i).widget() for i in range(toolbar.count())]
    assert order == [page.search, page.repo_filter, page.model_filter]
    assert not hasattr(page, "reset_btn")


def test_every_scan_row_ends_with_a_trash_can(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    last = page.table.columnCount() - 1
    assert page.table.horizontalHeaderItem(last).text() == ""
    for row in range(page.table.rowCount()):
        trash = page.table.cellWidget(row, last)
        assert trash.toolTip() == "Delete this scan" and not trash.icon().isNull()


def test_deleting_a_scan_asks_first_by_name(qapp, monkeypatch):
    from PyQt5.QtWidgets import QMessageBox
    asked = []

    def fake_question(parent, title, text, buttons, default):
        asked.append((title, text, default))
        return answers.pop(0)

    monkeypatch.setattr(QMessageBox, "question", fake_question)
    answers = [QMessageBox.No, QMessageBox.Yes]
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    got = []
    page.scan_delete_requested.connect(got.append)
    row = next(r for r in range(page.table.rowCount()) if page.table.item(r, 0).text() == "sample-org/payments-api")
    trash = page.table.cellWidget(row, page.TRASH_COLUMN)
    record_index = page.table.item(row, 0).data(Qt.UserRole)

    trash.click()  # No: nothing is deleted
    assert got == []
    trash.click()  # Yes
    assert got == [record_index]
    record = SEED_HISTORY[record_index]
    expected = f'Are you sure you want to delete "{record.repo} ({record.date}, {record.model})"?'
    assert asked[0] == ("Delete scan", expected, QMessageBox.No)  # the safe answer is the default


def test_a_filtered_list_deletes_the_right_scan(qapp, monkeypatch):
    from PyQt5.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.Yes)
    window = MainWindow(QSettings())
    window.history_page.repo_filter.setCurrentText("sample-org/payments-api")
    before = len(window.history)
    target = next(i for i, r in enumerate(window.history) if r.repo == "sample-org/payments-api")
    window.history_page.table.cellWidget(0, window.history_page.TRASH_COLUMN).click()

    assert len(window.history) == before - 1
    assert all(r.repo != "sample-org/payments-api" for r in window.history)
    assert window.history_page.summary.text().startswith(f"{before - 1} scans") or \
        window.history_page.repo_filter.currentText() != "sample-org/payments-api"
    window.findings_page.refresh(window.history)
    assert window.findings_page.repo_filter.findText("sample-org/payments-api") < 0
    assert target < before


def test_clicking_beside_the_trash_can_or_its_header_does_not_open_or_sort(qapp):
    page = HistoryPage()
    page.refresh(SEED_HISTORY)
    opened = []
    page.record_selected.connect(opened.append)
    page._select_record(0, page.TRASH_COLUMN)
    assert opened == []
    page._toggle_sort(page.TRASH_COLUMN)
    assert page._sort_column is None


def test_no_scans_left_after_deleting_every_one(qapp, monkeypatch):
    from PyQt5.QtWidgets import QMessageBox
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.Yes)
    window = MainWindow(QSettings())
    while window.history:
        window.history_page.table.cellWidget(0, window.history_page.TRASH_COLUMN).click()
    assert window.history_page.table.rowCount() == 0
    assert window.history_page.summary.text() == "0 scans · 0 findings · 0 verified"
    window.findings_page.refresh(window.history)
    assert window.findings_page.table.rowCount() == 0 and not window.findings_page.empty.isHidden()
