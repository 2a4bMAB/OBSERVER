"""
OBSERVER — Reports Page (Phase 3)
View, manage, and download generated PDF audit reports.
"""
import html as _html_mod
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QScrollArea, QTextEdit, QDialog, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from core.config import config
from core.database import get_db, Report, Scan, Target, Finding, Severity, ScanStatus, User
from core.rbac import session, Permission
from ui.design import theme as T
from ui.design.widgets import (
    PrimaryButton, SecondaryButton, DangerButton, Card,
    SectionLabel, AlertBanner, SeverityBadge
)


import logging
logger = logging.getLogger("observer.reports")


# ─── PDF Generation ───────────────────────────────────────────────────────────

def generate_pdf_report(scan_id: int) -> tuple[bool, str]:
    """
    Generate a PDF report for a given scan.
    Returns (success, message).
    """
    logger.info("--- generate_pdf_report() called for scan_id=%s ---", scan_id)
    db = get_db()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("Scan #%s not found in database", scan_id)
            return False, f"Scan #{scan_id} not found."

        target = db.query(Target).filter(Target.id == scan.target_id).first()
        target_url = target.url if target else f"Target #{scan.target_id}"
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(Finding.severity)
            .all()
        )
        operator = db.query(User).filter(User.id == scan.created_by).first()
        logger.info("Scan #%s details: target=%s, findings=%d, operator=%s",
                    scan_id, target_url, len(findings), getattr(operator, 'email', 'Unknown'))

        # Ensure reports directory exists
        reports_dir = config.REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"OBSERVER_Report_{ts}_Scan{scan_id}.pdf"
        filepath = reports_dir / filename

        logger.info("Building PDF file at: %s", filepath)
        _build_pdf(filepath, scan, target, findings, operator)
        logger.info("PDF document built successfully on disk (%s bytes)",
                    filepath.stat().st_size if filepath.exists() else 0)

        # Determine report creator ID — never allow NULL constraint failure
        creator_id = session.user_id if (session.is_authenticated and session.user_id) else scan.created_by
        if not creator_id:
            first_user = db.query(User).first()
            creator_id = first_user.id if first_user else 1

        logger.info("Inserting Report record into DB: scan_id=%s, created_by=%s, file_path=%s",
                    scan_id, creator_id, filepath)
        report = Report(
            scan_id=scan_id,
            created_by=creator_id,
            title=f"Audit Report — {target_url[:60]} — {datetime.now().strftime('%Y-%m-%d')}",
            file_path=str(filepath),
            created_at=datetime.now(timezone.utc),
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        logger.info("SUCCESS: Report #%s created and committed to database.", report.id)

        return True, f"Report saved: {filename}"
    except Exception as e:
        import traceback
        err_trace = traceback.format_exc()
        logger.error("EXCEPTION in generate_pdf_report(): %s\n%s", e, err_trace)
        return False, f"PDF generation failed: {e}"
    finally:
        db.close()


import re as _re

def _safe_para_text(text: str, max_len: int = 2000) -> str:
    """
    Sanitise arbitrary text (from DB / scan output) so it can be safely
    placed inside a ReportLab Paragraph without causing XML parse errors.
    - Strips ALL HTML tags (including <link>, <style>, <script>, etc.)
    - Escapes &, <, > that remain
    - Truncates to max_len characters to avoid huge blobs in the PDF
    """
    if not text:
        return ""
    # Remove every HTML tag
    clean = _re.sub(r"<[^>]+>", "", text)
    # Escape remaining XML special chars so ReportLab won't choke
    clean = _html_mod.escape(clean)
    # Truncate
    if len(clean) > max_len:
        clean = clean[:max_len] + " …"
    return clean


def _build_pdf(filepath: Path, scan, target, findings, operator):
    """Build the actual PDF document using ReportLab."""
    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "OBSTitle",
        parent=styles["Normal"],
        fontSize=22,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#111111"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "OBSSub",
        parent=styles["Normal"],
        fontSize=10,
        fontName="Helvetica",
        textColor=colors.HexColor("#666666"),
        spaceAfter=2,
    )
    section_style = ParagraphStyle(
        "OBSSection",
        parent=styles["Normal"],
        fontSize=11,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#111111"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "OBSBody",
        parent=styles["Normal"],
        fontSize=9,
        fontName="Helvetica",
        textColor=colors.HexColor("#333333"),
        leading=14,
        spaceAfter=4,
    )
    mono_style = ParagraphStyle(
        "OBSMono",
        parent=styles["Normal"],
        fontSize=8,
        fontName="Courier",
        textColor=colors.HexColor("#444444"),
        backColor=colors.HexColor("#f4f4f4"),
        leftIndent=8,
        rightIndent=8,
        spaceAfter=4,
        spaceBefore=4,
    )

    SEV_COLORS = {
        "critical": colors.HexColor("#ff2d2d"),
        "high":     colors.HexColor("#ff6b35"),
        "medium":   colors.HexColor("#f0b429"),
        "low":      colors.HexColor("#4caf82"),
        "info":     colors.HexColor("#5b9bd5"),
    }

    story = []

    # ── Cover / Header ─────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=3, color=colors.HexColor("#111111")))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("O B S E R V E R", title_style))
    story.append(Paragraph("Automated Web Vulnerability Audit Report", subtitle_style))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 6 * mm))

    # Metadata table
    meta_data = [
        ["Target URL", target.url if target else "N/A"],
        ["Target Label", target.label or "—"],
        ["Scan ID", f"#{scan.id}"],
        ["Operator", operator.full_name if operator else "Unknown"],
        ["Started", scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else "—"],
        ["Completed", scan.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.finished_at else "—"],
        ["Total Findings", str(len(findings))],
    ]

    meta_table = Table(meta_data, colWidths=[45 * mm, 120 * mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#111111")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, colors.HexColor("#cccccc")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8 * mm))

    # ── Summary ────────────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#eeeeee")))
    story.append(Spacer(1, 3 * mm))

    sev_counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity.value] += 1

    summary_data = [["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]]
    summary_data.append([str(sev_counts.get(s, 0)) for s in ["critical", "high", "medium", "low", "info"]])

    summary_table = Table(summary_data, colWidths=[33 * mm] * 5)
    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#ff2d2d")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#ff6b35")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#f0b429")),
        ("TEXTCOLOR", (3, 0), (3, -1), colors.HexColor("#4caf82")),
        ("TEXTCOLOR", (4, 0), (4, -1), colors.HexColor("#5b9bd5")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f9f9f9"), colors.white]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    # ── Findings ───────────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#eeeeee")))
    story.append(Spacer(1, 3 * mm))

    if not findings:
        story.append(Paragraph(
            "No vulnerabilities were detected during this scan.",
            body_style
        ))
    else:
        for i, f in enumerate(findings, 1):
            sev_color = SEV_COLORS.get(f.severity.value, colors.grey)
            block = []

            # Finding header
            header_data = [[
                Paragraph(f"#{i}  {_safe_para_text(f.title)}", ParagraphStyle(
                    "FindingTitle", parent=styles["Normal"],
                    fontSize=10, fontName="Helvetica-Bold",
                    textColor=colors.HexColor("#111111"),
                )),
                Paragraph(f.severity.value.upper(), ParagraphStyle(
                    "Sev", parent=styles["Normal"],
                    fontSize=9, fontName="Helvetica-Bold",
                    textColor=sev_color, alignment=1,
                )),
            ]]
            header_table = Table(header_data, colWidths=[145 * mm, 25 * mm])
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f4f4")),
                ("LINEABOVE", (0, 0), (-1, 0), 2, sev_color),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            block.append(header_table)

            # Details
            details_data = [
                ["OWASP Category", f"{f.owasp_category} — {f.owasp_name}"],
                ["Affected URL", f.url_affected or "N/A"],
                ["Parameter", f.parameter or "N/A"],
                ["Detected At", f.found_at.strftime("%Y-%m-%d %H:%M:%S UTC") if f.found_at else "—"],
            ]
            details_table = Table(details_data, colWidths=[40 * mm, 130 * mm])
            details_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("LINEBELOW", (0, -1), (-1, -1), 0.3, colors.HexColor("#dddddd")),
            ]))
            block.append(details_table)

            if f.description:
                block.append(Spacer(1, 2 * mm))
                block.append(Paragraph("<b>Description</b>", body_style))
                block.append(Paragraph(_safe_para_text(f.description), body_style))

            if f.evidence:
                block.append(Paragraph("<b>Evidence</b>", body_style))
                block.append(Paragraph(_safe_para_text(f.evidence, max_len=500), mono_style))

            block.append(Spacer(1, 5 * mm))
            story.append(KeepTogether(block))

    # ── Footer ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        f"Generated by OBSERVER Security Platform  ·  {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  ·  "
        f"Confidential — Do not distribute",
        ParagraphStyle(
            "Footer", parent=styles["Normal"],
            fontSize=7, fontName="Helvetica",
            textColor=colors.HexColor("#999999"),
            alignment=TA_CENTER,
        )
    ))

    doc.build(story)


# ─── Reports Page ─────────────────────────────────────────────────────────────

class ReportsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Topbar
        topbar = QFrame()
        topbar.setFixedHeight(56)
        topbar.setStyleSheet(
            f"background: {T.c('bg_secondary')}; border-bottom: 1px solid {T.c('border')};"
        )
        tb_layout = QHBoxLayout(topbar)
        tb_layout.setContentsMargins(24, 0, 24, 0)
        title_lbl = QLabel("Reports")
        title_lbl.setFont(QFont(T.FONT_UI, T.FONT_SIZE_LG, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {T.c('text_primary')}; background: transparent;")

        self.open_folder_btn = SecondaryButton("📁 Open Reports Folder")
        self.open_folder_btn.clicked.connect(self._open_folder)
        tb_layout.addWidget(title_lbl)
        tb_layout.addStretch()
        tb_layout.addWidget(self.open_folder_btn)
        layout.addWidget(topbar)

        # Content
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 20, 24, 24)
        cl.setSpacing(12)

        self.alert = AlertBanner("info")
        cl.addWidget(self.alert)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Report Title", "Created", "Scan ID", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().resizeSection(1, 160)
        self.table.horizontalHeader().resizeSection(2, 80)
        self.table.horizontalHeader().resizeSection(3, 140)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        cl.addWidget(self.table)

        layout.addWidget(content, 1)

    def on_enter(self):
        self._load_reports()

    def _load_reports(self):
        logger.info("--- _load_reports() called ---")
        db = get_db()
        try:
            q = db.query(Report)
            if not session.is_admin_user():
                logger.info("Non-admin: filtering reports by created_by=%s", session.user_id)
                q = q.filter(Report.created_by == session.user_id)
            else:
                logger.info("Admin: loading all reports")
            reports = q.order_by(Report.created_at.desc()).all()
            logger.info("Found %d report(s) in database", len(reports))

            self.table.clearContents()
            self.table.setRowCount(len(reports))
            self._report_ids = []
            for i, r in enumerate(reports):
                self.table.setItem(i, 0, QTableWidgetItem(r.title))
                self.table.setItem(
                    i, 1,
                    QTableWidgetItem(r.created_at.strftime("%Y-%m-%d %H:%M"))
                )
                self.table.setItem(i, 2, QTableWidgetItem(f"#{r.scan_id}"))

                # Action buttons cell
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(4, 2, 4, 2)
                actions_layout.setSpacing(6)

                open_btn = SecondaryButton("Open PDF")
                open_btn.setFixedHeight(28)
                open_btn.clicked.connect(
                    lambda checked, path=r.file_path: self._open_pdf(path)
                )
                actions_layout.addWidget(open_btn)

                if session.is_admin_user():
                    del_btn = DangerButton("Delete")
                    del_btn.setFixedHeight(28)
                    del_btn.clicked.connect(
                        lambda checked, rid=r.id: self._delete_report(rid)
                    )
                    actions_layout.addWidget(del_btn)

                self.table.setCellWidget(i, 3, actions_widget)
                self._report_ids.append(r.id)
            self.table.viewport().update()
        except Exception as e:
            logger.error("Error in _load_reports(): %s", e)
        finally:
            db.close()

    def _open_pdf(self, path: str):
        if not path or not Path(path).exists():
            self.alert.show_message("PDF file not found on disk.", auto_hide_ms=4000)
            return
        try:
            os.startfile(path)
        except Exception as e:
            self.alert.show_message(f"Cannot open PDF: {e}", auto_hide_ms=4000)

    def _open_folder(self):
        reports_dir = config.REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(f'explorer "{reports_dir}"')
        except Exception:
            pass

    def _delete_report(self, report_id: int):
        db = get_db()
        try:
            r = db.query(Report).filter(Report.id == report_id).first()
            if r:
                if r.file_path and Path(r.file_path).exists():
                    Path(r.file_path).unlink(missing_ok=True)
                db.delete(r)
                db.commit()
        finally:
            db.close()
        self._load_reports()
        self.alert.show_message("Report deleted.", auto_hide_ms=3000)
