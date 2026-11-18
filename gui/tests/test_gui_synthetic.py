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
from PyQt5.QtWidgets import QApplication, QDialog, QLabel, QMessageBox

from gui import main_gui as gui
from gui.main_gui import HistoryPage, MainWindow, ScanPage
from gui.data.mock_data import (
    DISABLED_MODELS, MODEL_IDS, SAMPLE_FINDINGS, SAMPLE_OUTPUT, SAMPLE_SNIPPETS, SEED_HISTORY,
    SEVERITY_ORDER, Finding, code_url, sample_fix, sample_snippet, split_location,
)


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
    return [page.table.item(r, col).text() for r in range(page.table.rowCount())]


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

def test_new_scan_page_is_empty_and_actions_disabled(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.reset()
    assert page.table.rowCount() == 0
    assert page.output.toPlainText() == ""
    for btn in (page.fix_btn, page.verify_btn, page.report_btn):
        assert not btn.isEnabled()


def test_empty_history_page(qapp):
    page = HistoryPage()
    page.refresh([])
    assert page.table.rowCount() == 0
    assert [label.text() for label in page.card_values.values()] == ["0", "0", "0"]


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

def test_actions_enable_only_with_a_selection(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table(SAMPLE_FINDINGS)  # selects row 0
    assert all(b.isEnabled() for b in (page.fix_btn, page.verify_btn, page.report_btn))
    page.table.clearSelection()
    assert not any(b.isEnabled() for b in (page.fix_btn, page.verify_btn, page.report_btn))


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


def test_verify_and_report_are_not_implemented(qapp, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "information",
                        lambda *args, **kwargs: shown.append(args[2]))
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table([replace(f) for f in SAMPLE_FINDINGS])
    before = table_column(page, 4)

    for btn in (page.verify_btn, page.report_btn):
        btn.click()

    assert len(shown) == 2
    assert all("not implemented" in msg for msg in shown)
    assert table_column(page, 4) == before


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
    assert not window.back_button.isEnabled()
    assert not window.forward_button.isEnabled()

    window.home_page.new_scan_requested.emit()
    assert window.stack.currentIndex() == window.SCAN
    window.go_back()
    assert window.stack.currentIndex() == window.HOME

    window.home_page.history_requested.emit()
    assert window.stack.currentIndex() == window.HISTORY
    window.show_stats()
    assert window.stack.currentIndex() == window.STATS

    window.go_back()
    assert window.stack.currentIndex() == window.HISTORY
    assert window.back_button.isEnabled()
    assert window.forward_button.isEnabled()
    window.go_forward()
    assert window.stack.currentIndex() == window.STATS
    assert not window.forward_button.isEnabled()


def test_navigation_shortcuts_and_branching_history(qapp):
    window = MainWindow()
    window.show_history()
    window.show_stats()

    back_event = QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.ControlModifier)
    QApplication.sendEvent(window.home_button, back_event)
    assert window.stack.currentIndex() == window.HISTORY

    command_forward_event = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Right, Qt.MetaModifier)
    QApplication.sendEvent(window.home_button, command_forward_event)
    assert window.stack.currentIndex() == window.STATS

    command_back_event = QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.MetaModifier)
    QApplication.sendEvent(window.home_button, command_back_event)
    assert window.stack.currentIndex() == window.HISTORY

    forward_event = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Right, Qt.ControlModifier)
    QApplication.sendEvent(window.home_button, forward_event)
    assert window.stack.currentIndex() == window.STATS

    window.go_back()
    window.show_home()
    assert window.stack.currentIndex() == window.HOME
    assert not window.forward_button.isEnabled()
    assert window.back_button.text() == "‹"
    assert window.forward_button.text() == "›"
    assert window.back_button.objectName() == "backNavigation"
    assert window.forward_button.objectName() == "forwardNavigation"


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


def test_main_window_defines_show_stats_once():
    # Guards against the duplicate definition that was removed.
    import inspect
    source = inspect.getsource(gui.MainWindow)
    assert source.count("def show_stats") == 1


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


# Per-finding actions: Fix, Accept, Ignore, View in code (all mocked)

def scan_with_findings(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    run_demo_scan(page)
    return page


def select_finding(page, finding_id):
    row = next(i for i, f in enumerate(page._rows) if f.id == finding_id)
    page.table.selectRow(row)
    return page._current_finding()


def stub_dialog(monkeypatch, result, reason_index=0, note=""):
    def fake_exec(self):
        self.reason.setCurrentIndex(reason_index)
        self.note.setPlainText(note)
        return result
    monkeypatch.setattr(gui.DecisionDialog, "exec_", fake_exec)


def test_detail_panel_shows_the_selected_finding(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    assert finding.id in page.detail_heading.text()
    assert page.detail_title.text() == finding.title
    assert finding.location in page.code_link.text()
    assert page.decision_label.isHidden()


def test_detail_panel_without_selection_disables_all_actions(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.reset()
    assert "No finding selected" in page.detail_heading.text()
    buttons = (page.fix_btn, page.accept_btn, page.ignore_btn, page.verify_btn, page.report_btn)
    assert not any(b.isEnabled() for b in buttons)
    assert page.code_link.isHidden()


def test_fix_proposes_a_sample_fix_and_marks_the_row(qapp, monkeypatch):
    shown = []
    monkeypatch.setattr(QMessageBox, "information",
                        lambda *args, **kwargs: shown.append(args[2]))
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.fix_btn.click()

    assert finding.status == "Fix proposed"
    assert table_column(page, 4)[page._rows.index(finding)] == "Fix proposed"
    assert sample_fix(finding) in shown[0] and "Mocked" in shown[0]


def test_accept_records_reason_and_context(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted, reason_index=1, note="  Reviewed with the owner  ")
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.accept_btn.click()

    assert (finding.decision, finding.status) == ("Accepted", "Accepted")
    assert finding.reason == gui.ACCEPT_REASONS[1]
    assert finding.note == "Reviewed with the owner"
    assert table_column(page, 4)[page._rows.index(finding)] == "Accepted"
    assert "Reviewed with the owner" in page.decision_label.text()


def test_ignore_records_reason_and_context(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted, reason_index=0, note="Test code only")
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-006")
    page.ignore_btn.click()

    assert (finding.decision, finding.status) == ("Ignored", "Ignored")
    assert finding.reason == gui.IGNORE_REASONS[0]
    assert "Ignored: False positive" in page.decision_label.text()


def test_cancelled_decision_changes_nothing(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Rejected, note="should not be saved")
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    before = finding.status
    page.ignore_btn.click()

    assert finding.status == before
    assert (finding.decision, finding.reason, finding.note) == ("", "", "")


def test_decisions_never_change_sample_data_or_other_scans(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted)
    originals = [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS]
    window = MainWindow()
    run_demo_scan(window.scan_page)
    select_finding(window.scan_page, "VULN-005")
    window.scan_page.accept_btn.click()

    assert [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS] == originals
    seeded = [f for r in window.history[1:] for f in r.findings if f.id == "VULN-005"]
    assert seeded and all(f.decision == "" for f in seeded)

    run_demo_scan(window.scan_page)  # a second scan starts clean
    assert all(f.decision == "" for f in window.scan_page._rows)


def test_decision_is_kept_when_a_past_scan_is_reopened(qapp, monkeypatch):
    stub_dialog(monkeypatch, QDialog.Accepted, note="kept")
    window = MainWindow()
    run_demo_scan(window.scan_page)
    select_finding(window.scan_page, "VULN-005")
    window.scan_page.ignore_btn.click()

    window.open_record(1)  # some other scan
    window.open_record(0)  # back to the one just decided on
    finding = select_finding(window.scan_page, "VULN-005")
    assert finding.decision == "Ignored" and finding.note == "kept"


def test_decision_dialog_lists_the_right_reasons_and_context(qapp):
    finding = replace(SAMPLE_FINDINGS[0])
    accept = gui.DecisionDialog(None, finding, "Accept")
    ignore = gui.DecisionDialog(None, finding, "Ignore")
    assert [accept.reason.itemText(i) for i in range(accept.reason.count())] == gui.ACCEPT_REASONS
    assert [ignore.reason.itemText(i) for i in range(ignore.reason.count())] == gui.IGNORE_REASONS
    assert (accept.decision, ignore.decision) == ("Accepted", "Ignored")
    assert sample_fix(finding) in accept.findChildren(gui.QLabel)[0].text()


def test_view_in_code_shows_a_sample_snippet_with_the_flagged_line(qapp, monkeypatch):
    opened = []
    monkeypatch.setattr(gui.CodeViewDialog, "exec_", lambda self: opened.append(self))
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-003")
    page.code_link.click()

    code = opened[0].code.toPlainText()
    _path, line = split_location(finding.location)
    assert f"> {line:>4} |" in code
    assert code_url(finding).endswith(f"#L{line}")


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
    assert window.stack.count() == 4  # the API connector is a popup, not a page


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


def test_clicking_the_status_pill_opens_the_api_settings(qapp):
    window = MainWindow()
    window.status_pill.clicked.emit()
    assert window.settings_dialog.isVisible()
    assert window.settings_dialog.isAncestorOf(window.connector_page)
    window.settings_dialog.close()


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


def test_getting_started_reminder_respects_dont_show_again(qapp, tmp_path):
    from PyQt5.QtCore import QSettings
    settings = QSettings(str(tmp_path / "vulngui.ini"), QSettings.IniFormat)
    window = MainWindow(settings=settings)
    assert not gui.reminder_hidden(settings)

    dialog = window.maybe_show_reminder()
    assert dialog is not None and len(dialog.STEPS) == 3
    dialog.close_btn.click()  # closed without ticking the box: it will show again
    assert not gui.reminder_hidden(settings)

    dialog = window.maybe_show_reminder()
    dialog.dont_show.setChecked(True)
    dialog.close_btn.click()
    assert gui.reminder_hidden(settings)
    assert window.maybe_show_reminder() is None


def test_reminder_is_not_shown_just_by_creating_the_window(qapp, tmp_path):
    from PyQt5.QtCore import QSettings
    window = MainWindow(settings=QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat))
    assert window.reminder is None


# Home page

def test_home_page_greeting_and_new_scan_above_the_cards(qapp):
    home = gui.HomePage()
    heading = home.findChild(gui.QLabel, "homeHeading")
    assert heading.text() == "Welcome back, dev"
    cards = home.findChildren(gui.ModuleCard)
    assert [c.findChild(gui.QLabel, "cardTitle").text() for c in cards] == ["Scan History", "Stats"]

    home.resize(1200, 800)
    home.show()
    qapp.processEvents()
    assert home.new_scan_btn.geometry().bottom() < min(c.geometry().top() for c in cards)
    home.close()


def test_home_page_has_no_getting_started_panel_or_api_card(qapp):
    home = gui.HomePage()
    texts = {label.text() for label in home.findChildren(gui.QLabel)}
    assert "GETTING STARTED" not in texts and "API Connector" not in texts
    assert "Dashboard" not in texts


def test_home_buttons_emit_their_signals(qapp):
    home = gui.HomePage()
    got = []
    home.new_scan_requested.connect(lambda: got.append("new"))
    home.history_requested.connect(lambda: got.append("history"))
    home.stats_requested.connect(lambda: got.append("stats"))
    home.new_scan_btn.click()
    cards = home.findChildren(gui.ModuleCard)
    cards[0].click()
    cards[1].click()
    assert got == ["new", "history", "stats"]


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
    assert page.card_values["Scans"].text() == "2"

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

def test_stats_page_shows_the_aggregate_then_one_repo(qapp):
    from gui.data.mock_data import BURNDOWN_BY_REPO, burndown_series, burndown_totals
    stats = gui.StatsPage()
    assert stats.repo_box.itemText(0) == "All repos"
    open_now, closed, total = burndown_totals(burndown_series())
    assert [stats.card_values[k].text() for k in ("Open", "Closed", "Total")] == [
        str(open_now), str(closed), str(total)]
    assert [v for _, v in stats.chart.points] == [
        sum(week) for week in zip(*BURNDOWN_BY_REPO.values())]

    stats.repo_box.setCurrentText("sample-org/payments-api")
    assert [v for _, v in stats.chart.points] == BURNDOWN_BY_REPO["sample-org/payments-api"]
    assert stats.card_values["Total"].text() == "1"
    stats.chart.resize(900, 400)
    assert not stats.chart.grab().isNull()


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


def test_scan_log_can_be_collapsed(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    assert not page.output.isHidden()
    page.log_toggle.click()
    assert page.output.isHidden() and "▸" in page.log_toggle.text()
    page.log_toggle.click()
    assert not page.output.isHidden() and "▾" in page.log_toggle.text()


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
    assert page.result_dialog is None


def test_finishing_a_scan_shows_a_red_result_card(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    run_demo_scan(page)
    card = page.result_dialog
    assert card is not None and card.level == "high"
    assert "7 vulnerabilities detected" in card.banner_label.text()
    assert [c.text() for c in card.chips] == ["3 High", "4 Low"]
    assert not card.view_btn.isHidden()
    card.view_btn.click()
    assert card.result() == QDialog.Accepted


def test_result_card_levels_and_wording(qapp):
    def card(findings):
        return gui.ScanResultDialog(None, findings)

    none = card([])
    assert none.level == "none" and "No vulnerabilities found" in none.banner_label.text()
    assert none.view_btn.isHidden() and none.chips == []

    low_only = card([Finding("A", "Low", "t", "a.py:1", "Open"), Finding("B", "Medium", "t", "a.py:2", "Open")])
    assert low_only.level == "other"
    assert "2 vulnerabilities detected" in low_only.banner_label.text()

    one = card([Finding("A", "High+", "t", "a.py:1", "Open")])
    assert one.level == "high" and "1 vulnerability detected" in one.banner_label.text()


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


def test_scanning_screen_is_centred_and_the_result_card_sits_at_the_bottom(qapp):
    window = MainWindow()
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
    assert page._dim is None  # the window is usable again
    card = page.result_dialog
    box = card.frameGeometry()
    assert abs(box.center().x() - win.center().x()) <= 3
    assert box.top() > win.center().y() and box.bottom() <= win.bottom()
    assert card.windowModality() == Qt.NonModal  # the findings stay clickable
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


def test_result_card_text_is_one_size(qapp):
    import re
    card = gui.ScanResultDialog(None, SAMPLE_FINDINGS)
    sizes = {re.search(r"font-size: (\d+)px", label.styleSheet()).group(1)
             for label in [card.banner_label] + card.chips}
    assert sizes == {str(card.TEXT_SIZE)}


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


def test_status_change_keeps_the_row_colour(qapp, monkeypatch):
    from PyQt5.QtGui import QColor
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.fix_btn.click()
    row = page._rows.index(finding)
    assert page.table.item(row, 4).text() == "Fix proposed"
    assert page.table.item(row, 4).background().color() == QColor(gui.SEVERITY_COLORS["High"][0])


def test_tracker_counts_use_the_tier_colours(qapp):
    tracker = gui.SeverityTracker()
    for tier, label in tracker.counts.items():
        assert gui.SEVERITY_COLORS[tier][1].lower() in label.styleSheet().lower()


def test_result_card_chips_use_the_tier_colours(qapp):
    card = gui.ScanResultDialog(None, SAMPLE_FINDINGS)
    high_bg, high_fg = gui.SEVERITY_COLORS["High"]
    low_bg, low_fg = gui.SEVERITY_COLORS["Low"]
    assert high_bg in card.chips[0].styleSheet() and high_fg in card.chips[0].styleSheet()
    assert low_bg in card.chips[1].styleSheet() and low_fg in card.chips[1].styleSheet()


def test_logo_button_text_is_larger(qapp):
    assert gui.HOME_BUTTON_PX == 28
    block = gui.STYLE.split("QPushButton#home {")[1].split("}")[0]
    assert f"font-size: {gui.HOME_BUTTON_PX}px" in block
    window = MainWindow()
    assert window.home_button.minimumHeight() >= 52


def test_help_button_reopens_getting_started_even_when_it_was_turned_off(qapp, tmp_path):
    from PyQt5.QtCore import QSettings
    settings = QSettings(str(tmp_path / "vulngui.ini"), QSettings.IniFormat)
    gui.set_reminder_hidden(settings, True)
    window = MainWindow(settings=settings)
    assert window.maybe_show_reminder() is None  # the launch reminder stays off

    window.help_button.click()
    dialog = window.reminder
    assert dialog is not None and dialog.isVisible()
    assert dialog.dont_show.isChecked()  # shows the saved choice

    dialog.dont_show.setChecked(False)  # turn the launch reminder back on
    dialog.close_btn.click()
    assert not gui.reminder_hidden(settings)
    assert window.maybe_show_reminder() is not None
    window.reminder.close()
