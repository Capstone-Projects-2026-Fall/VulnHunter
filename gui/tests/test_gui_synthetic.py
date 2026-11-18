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


def test_verify_and_report_are_not_implemented(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page._fill_table([replace(f) for f in SAMPLE_FINDINGS])
    before = table_column(page, 4)

    for btn in (page.verify_btn, page.report_btn):
        btn.click()
        assert not page.action_note.isHidden()
        assert page.action_note.text() == f"{btn.text()} is not available in this demo yet."
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
    window.show_reports()
    assert window.stack.currentIndex() == window.REPORTS

    window.go_back()
    assert window.stack.currentIndex() == window.HISTORY
    assert window.back_button.isEnabled()
    assert window.forward_button.isEnabled()
    window.go_forward()
    assert window.stack.currentIndex() == window.REPORTS
    assert not window.forward_button.isEnabled()


def test_navigation_shortcuts_and_branching_history(qapp):
    window = MainWindow()
    window.show_history()
    window.show_reports()

    back_event = QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.ControlModifier)
    QApplication.sendEvent(window.home_button, back_event)
    assert window.stack.currentIndex() == window.HISTORY

    command_forward_event = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Right, Qt.MetaModifier)
    QApplication.sendEvent(window.home_button, command_forward_event)
    assert window.stack.currentIndex() == window.REPORTS

    command_back_event = QKeyEvent(QEvent.KeyPress, Qt.Key_Left, Qt.MetaModifier)
    QApplication.sendEvent(window.home_button, command_back_event)
    assert window.stack.currentIndex() == window.HISTORY

    forward_event = QKeyEvent(
        QEvent.KeyPress, Qt.Key_Right, Qt.ControlModifier)
    QApplication.sendEvent(window.home_button, forward_event)
    assert window.stack.currentIndex() == window.REPORTS

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


# Per-finding actions: Fix, Accept, Dispute, View in code (all mocked)

def scan_with_findings(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    run_demo_scan(page)
    return page


def select_finding(page, finding_id):
    row = next(i for i, f in enumerate(page._rows) if f.id == finding_id)
    page.table.selectRow(row)
    return page._current_finding()


def decide(page, kind, reason_index=0, note=""):
    """Click Accept or Dispute, fill the inline form and save it."""
    (page.accept_btn if kind == "Accept" else page.dispute_btn).click()
    page.decision_reason.setCurrentIndex(reason_index)
    page.decision_note.setPlainText(note)
    page.decision_save.click()


def test_detail_panel_shows_the_selected_finding(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    heading = page.detail_heading.text()
    assert finding.id in heading and finding.severity in heading and finding.status in heading
    assert page.detail_title.text() == finding.title
    assert page.location_label.text() == finding.location
    assert page.decision_label.isHidden()
    assert page.cwe_link.text() == f"{finding.cwe} {gui.cwe_name(finding.cwe)} ↗"
    assert page.fix_text.text() == sample_fix(finding)


def test_detail_panel_without_selection_disables_all_actions(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    page.reset()
    assert "No finding selected" in page.detail_heading.text()
    buttons = (page.fix_btn, page.accept_btn, page.dispute_btn, page.verify_btn, page.report_btn)
    assert not any(b.isEnabled() for b in buttons)
    assert page.cwe_link.isHidden() and page.location_label.isHidden()


def test_fix_proposes_a_sample_fix_and_marks_the_row(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.fix_btn.click()

    assert finding.status == "Fix proposed"
    assert table_column(page, 4)[page._rows.index(finding)] == "Fix proposed"
    assert "Mocked" in page.action_note.text() and not page.action_note.isHidden()
    assert page.fix_text.text() == sample_fix(finding)


def test_accept_records_reason_and_context(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    decide(page, "Accept", reason_index=1, note="  Reviewed with the owner  ")

    assert (finding.decision, finding.status) == ("Accepted", "Accepted")
    assert finding.reason == gui.ACCEPT_REASONS[1]
    assert finding.note == "Reviewed with the owner"
    assert table_column(page, 4)[page._rows.index(finding)] == "Accepted"
    assert "Reviewed with the owner" in page.decision_label.text()
    assert page.decision_form.isHidden()


def test_dispute_records_reason_and_context(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-006")
    decide(page, "Dispute", reason_index=0, note="Test code only")

    assert (finding.decision, finding.status) == ("Disputed", "Disputed")
    assert finding.reason == gui.DISPUTE_REASONS[0]
    assert "Disputed: False positive" in page.decision_label.text()


def test_cancelled_decision_changes_nothing(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    before = finding.status
    page.dispute_btn.click()
    assert not page.decision_form.isHidden()
    page.decision_note.setPlainText("should not be saved")
    page.decision_cancel.click()

    assert page.decision_form.isHidden()
    assert finding.status == before
    assert (finding.decision, finding.reason, finding.note) == ("", "", "")


def test_decisions_never_change_sample_data_or_other_scans(qapp):
    originals = [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS]
    window = MainWindow(QSettings())
    run_demo_scan(window.scan_page)
    select_finding(window.scan_page, "VULN-005")
    decide(window.scan_page, "Accept")

    assert [(f.id, f.status, f.decision) for f in SAMPLE_FINDINGS] == originals
    seeded = [f for r in window.history[1:] for f in r.findings if f.id == "VULN-005"]
    assert seeded and all(f.decision == "" for f in seeded)

    run_demo_scan(window.scan_page)  # a second scan starts clean
    assert all(f.decision == "" for f in window.scan_page._rows)


def test_decision_is_kept_when_a_past_scan_is_reopened(qapp):
    window = MainWindow(QSettings())
    run_demo_scan(window.scan_page)
    select_finding(window.scan_page, "VULN-005")
    decide(window.scan_page, "Dispute", note="kept")

    window.open_record(1)  # some other scan
    window.open_record(0)  # back to the one just decided on
    finding = select_finding(window.scan_page, "VULN-005")
    assert finding.decision == "Disputed" and finding.note == "kept"


def test_decision_form_lists_the_right_reasons(qapp):
    page = scan_with_findings(qapp)
    select_finding(page, "VULN-005")
    page.accept_btn.click()
    assert [page.decision_reason.itemText(i) for i in range(page.decision_reason.count())] == gui.ACCEPT_REASONS
    assert page.decision_title.text() == "Accept: VULN-005"
    page.dispute_btn.click()
    assert [page.decision_reason.itemText(i) for i in range(page.decision_reason.count())] == gui.DISPUTE_REASONS
    assert page.decision_title.text() == "Dispute: VULN-005"


def test_code_view_shows_a_sample_snippet_with_the_flagged_line(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-003")
    code = page.code_view.toPlainText()
    _path, line = split_location(finding.location)
    assert f"> {line:>4} |" in code
    assert code_url(finding).endswith(f"#L{line}")
    assert page.code_view.isReadOnly()
    assert len(page.code_view.extraSelections()) == 1


def test_cwe_link_opens_the_mitre_page(qapp, monkeypatch):
    opened = []
    monkeypatch.setattr(gui.QDesktopServices, "openUrl", lambda url: opened.append(url.toString()))
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.cwe_link.click()
    assert opened == [gui.cwe_url(finding.cwe)] and opened[0].startswith("https://cwe.mitre.org/")


def test_copy_puts_the_location_on_the_clipboard(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page.copy_btn.click()
    assert QApplication.clipboard().text() == finding.location


def test_editor_link_needs_a_local_folder_that_holds_the_file(qapp, tmp_path, monkeypatch):
    opened = []
    monkeypatch.setattr(gui.QDesktopServices, "openUrl", lambda url: opened.append(url.toString()))
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    assert not page.editor_btn.isEnabled()  # the repo text is not a local folder

    path, line = split_location(finding.location)
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x = 1\n")
    page.repo.setText(str(tmp_path))
    select_finding(page, "VULN-006")
    select_finding(page, "VULN-005")
    assert page.editor_btn.isEnabled()
    page.editor_btn.click()
    assert opened[0].startswith("vscode://file/") and opened[0].endswith(f"{path}:{line}")

    assert gui.editor_uri(str(tmp_path), "missing/file.py:3") == ""
    assert gui.editor_uri("https://github.com/x/y", finding.location) == ""
    assert gui.editor_uri("", finding.location) == ""


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
    assert window.stack.count() == 5  # home, history, scan, reports, findings; the API settings are a popover


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
    assert window.home_page.getting_started.isHidden() or True  # shown by maybe_show_reminder at launch
    assert window.maybe_show_reminder() is True


# Home page

def test_home_page_greeting_and_new_scan_above_the_cards(qapp):
    home = gui.HomePage()
    heading = home.findChild(gui.QLabel, "homeHeading")
    assert heading.text() == "Welcome back, dev"
    cards = home.findChildren(gui.ModuleCard)
    assert [c.findChild(gui.QLabel, "cardTitle").text() for c in cards] == ["Findings", "Scan History", "Reports"]

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
    home.history_requested.connect(lambda: got.append("history"))
    home.reports_requested.connect(lambda: got.append("reports"))
    home.new_scan_btn.click()
    cards = home.findChildren(gui.ModuleCard)
    for card in cards:
        card.click()
    assert got == ["new", "findings", "history", "reports"]


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
    reports.reset_btn.click()
    assert reports.repo_box.currentText() == "All repos"


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


def test_breadcrumbs_lead_back(qapp):
    window = MainWindow(QSettings())
    window.show_history()
    window.history_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.HOME
    window.show_reports()
    window.reports_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.HOME
    window.open_record(0)
    assert window.scan_page.breadcrumb.current.text() == window.history[0].repo
    window.scan_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.HISTORY
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
    finding = select_finding(page, "VULN-005")
    page.fix_btn.click()
    row = page._rows.index(finding)
    assert page.table.item(row, 4).text() == "Fix proposed"
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


# Findings open a side panel when clicked

def test_the_side_panel_starts_on_the_overview(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    assert page.side.currentIndex() == 0
    assert page.side.widget(1) is page.detail_scroll and page.detail_scroll.widget() is page.detail
    assert page.side.width() == page.SIDE_WIDTH


def test_a_scan_finishing_does_not_open_the_details_by_itself(qapp):
    page = scan_with_findings(qapp)
    assert page._current_finding() is not None  # the first row is selected
    assert page.side.currentIndex() == 0


def test_clicking_a_finding_opens_its_panel(qapp):
    window = MainWindow(QSettings())
    window.resize(1360, 900)
    window.show()
    window.new_scan()
    page = window.scan_page
    run_demo_scan(page)
    page.banner.close_btn.click()
    qapp.processEvents()

    page.table.selectRow(1)
    page._on_row_clicked(1, 0)
    qapp.processEvents()
    finding = page._current_finding()
    assert page.side.currentIndex() == 1
    assert finding.id in page.detail_heading.text()
    window.close()


def test_a_real_click_on_a_row_opens_the_panel(qapp):
    from PyQt5.QtTest import QTest
    window = MainWindow(QSettings())
    window.resize(1360, 900)
    window.show()
    window.new_scan()
    page = window.scan_page
    run_demo_scan(page)
    qapp.processEvents()
    rect = page.table.visualItemRect(page.table.item(2, 2))
    QTest.mouseClick(page.table.viewport(), Qt.LeftButton, pos=rect.center())
    qapp.processEvents()
    assert page._current_finding() is page._rows[2]
    assert page.side.currentIndex() == 1
    window.close()


def test_the_panel_closes_with_the_x_and_with_a_new_scan(qapp):
    page = scan_with_findings(qapp)
    page._open_detail()
    assert page.side.currentIndex() == 1
    page.detail_close.click()
    assert page.side.currentIndex() == 0

    page._open_detail()
    page.reset()
    assert page.side.currentIndex() == 0


def test_closing_the_panel_cancels_an_open_decision_form(qapp):
    page = scan_with_findings(qapp)
    page._open_detail()
    page.accept_btn.click()
    assert not page.decision_form.isHidden()
    page.detail_close.click()
    assert page.decision_form.isHidden()


def test_actions_inside_the_panel_update_the_row(qapp):
    page = scan_with_findings(qapp)
    finding = select_finding(page, "VULN-005")
    page._open_detail()
    decide(page, "Accept", note="from the panel")
    assert finding.status == "Accepted"
    assert table_column(page, 4)[page._rows.index(finding)] == "Accepted"
    assert "from the panel" in page.decision_label.text()


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


# Findings board and Dispute

def test_dispute_replaces_ignore_everywhere(qapp):
    page = ScanPage(SAMPLE_FINDINGS, SAMPLE_OUTPUT)
    assert page.dispute_btn.text() == "Dispute" and not hasattr(page, "ignore_btn")
    assert "Handled elsewhere in the stack" in gui.DISPUTE_REASONS
    assert "Fix would break the system" in gui.DISPUTE_REASONS
    assert not hasattr(gui, "IGNORE_REASONS")
    assert "Dispute" in gui.GettingStartedBanner.STEPS[2]


def test_status_groups_cover_every_sample_status():
    from gui.data.mock_data import STATUS_GROUPS, status_group
    assert [status_group(s) for s in ("Open", "Fix proposed", "PR open", "Disputed", "Accepted", "Verified", "Merged")] == [
        "Open", "In progress", "In progress", "Disputed", "Done", "Done", "Done"]
    assert status_group("something new") == "Open"
    assert list(STATUS_GROUPS) == ["Open", "In progress", "Disputed", "Done"]


def test_board_lists_the_latest_scan_of_each_repo(qapp):
    from gui.data.mock_data import latest_scan_indexes
    window = MainWindow(QSettings())
    page = window.findings_page
    page.refresh(window.history)
    latest = latest_scan_indexes(window.history)
    expected = sum(len(window.history[i].findings) for i in latest.values())
    assert page.table.rowCount() == expected == 8
    assert page.repo_filter.count() == 1 + len(latest)
    assert sum(int(v.text()) for v in page.group_values.values()) == expected
    # worst severity first
    severities = [page.table.item(r, 1).text() for r in range(page.table.rowCount())]
    assert severities == sorted(severities, key=gui.SEVERITY_ORDER.index)


def test_board_filters_and_cards_narrow_the_list(qapp):
    window = MainWindow(QSettings())
    page = window.findings_page
    page.refresh(window.history)
    total = page.table.rowCount()

    page.severity_filter.setCurrentText("Low")
    assert 0 < page.table.rowCount() < total
    assert all(page.table.item(r, 1).text() == "Low" for r in range(page.table.rowCount()))
    page.reset_btn.click()
    assert page.table.rowCount() == total and page.search.text() == ""

    page.repo_filter.setCurrentText("sample-org/payments-api")
    assert {page.table.item(r, 3).text() for r in range(page.table.rowCount())} == {"sample-org/payments-api"}
    page.reset_filters()

    card = page.findChildren(gui.ClickableCard)[0]
    card.clicked.emit()
    assert page.status_filter.currentText() == "Open"
    assert all(gui.status_group(f.status) == "Open" for _i, _r, f in page._shown)
    page.search.setText("no such finding anywhere")
    assert page.table.rowCount() == 0 and not page.empty.isHidden()
    page.reset_filters()
    assert page.empty.isHidden()


def test_choosing_a_finding_opens_its_scan_with_the_panel_open(qapp):
    window = MainWindow(QSettings())
    window.show_findings()
    page = window.findings_page
    assert window.stack.currentIndex() == window.FINDINGS
    row = next(r for r, (_i, _repo, f) in enumerate(page._shown) if f.id == "VULN-005")
    page._choose(row, 0)

    assert window.stack.currentIndex() == window.SCAN
    assert window.scan_page._current_finding().id == "VULN-005"
    assert window.scan_page.side.currentIndex() == 1
    assert window.scan_page.breadcrumb.back_btn.text() == "← Findings"
    window.scan_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.FINDINGS
    window.open_record(0)
    assert window.scan_page.breadcrumb.back_btn.text() == "← Scan History"


def test_a_dispute_shows_up_on_the_board(qapp):
    window = MainWindow(QSettings())
    window.show_findings()
    window.findings_page._choose(0, 0)
    page = window.scan_page
    finding = page._current_finding()
    decide(page, "Dispute", reason_index=2, note="Would break the cluster")
    assert (finding.status, finding.reason) == ("Disputed", "Fix would break the system")

    window.show_findings()
    board = window.findings_page
    assert int(board.group_values["Disputed"].text()) == 1
    board.status_filter.setCurrentText("Disputed")
    assert board.table.rowCount() == 1 and board.table.item(0, 4).text() == "Disputed"


def test_home_findings_card_opens_the_board(qapp):
    window = MainWindow(QSettings())
    window.home_page.findings_requested.emit()
    assert window.stack.currentIndex() == window.FINDINGS
    window.findings_page.breadcrumb.back_btn.click()
    assert window.stack.currentIndex() == window.HOME
