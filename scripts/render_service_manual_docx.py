"""Render the Korean service manual to a Microsoft Word DOCX file.

Requires python-docx 1.2.0. Install separately with
``python -m pip install python-docx==1.2.0`` before running this script.
"""

from __future__ import annotations

import re
from pathlib import Path
from zipfile import ZipFile

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Docs" / "Core_mds" / "mcp-guard-서비스-설명서.md"
TARGET = ROOT / "Docs" / "Core_mds" / "mcp-guard-서비스-설명서.docx"
FONT = "맑은 고딕"


def set_font(style, size: float, *, bold: bool = False, color: tuple[int, int, int] | None = None) -> None:
    style.font.name = FONT
    style.font.size = Pt(size)
    style.font.bold = bold
    if color:
        style.font.color.rgb = RGBColor(*color)
    style._element.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), FONT)


def add_inline(paragraph, source: str) -> None:
    """Keep text exact while applying Markdown's simple bold/code emphasis."""
    parts = re.split(r"(\*\*[^*]+\*\*|`[^`]+`)", source)
    for part in parts:
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`"):
            run = paragraph.add_run(part[1:-1])
            run.font.name = "Consolas"
            run.font.size = Pt(9)
        else:
            paragraph.add_run(part)


def add_page_number(paragraph) -> None:
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run()
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    run._r.addnext(field)


def build() -> tuple[int, int]:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    document = Document()
    section = document.sections[0]
    section.page_width, section.page_height = Cm(21), Cm(29.7)
    section.top_margin = Cm(2.2)
    section.bottom_margin = Cm(2.1)
    section.left_margin = Cm(2.4)
    section.right_margin = Cm(2.4)

    normal = document.styles["Normal"]
    set_font(normal, 10.5, color=(32, 40, 52))
    normal.paragraph_format.space_after = Pt(7)
    normal.paragraph_format.line_spacing = 1.25

    set_font(document.styles["Title"], 22, bold=True, color=(17, 47, 80))
    set_font(document.styles["Heading 1"], 15, bold=True, color=(17, 47, 80))
    set_font(document.styles["Heading 2"], 12, bold=True, color=(40, 76, 110))
    document.styles["Heading 1"].paragraph_format.space_before = Pt(17)
    document.styles["Heading 1"].paragraph_format.space_after = Pt(6)
    document.styles["Heading 2"].paragraph_format.space_before = Pt(12)
    document.styles["Heading 2"].paragraph_format.space_after = Pt(4)

    document.core_properties.title = "mcp-guard 서비스 설명서"
    document.core_properties.subject = "MCP 보호 서비스 구조, 공격 유형, MVP와 Progress map"
    document.core_properties.language = "ko-KR"

    count = 0
    for original in lines:
        line = original.strip()
        if not line:
            continue
        if line.startswith("# "):
            document.add_paragraph(line[2:], style="Title")
        elif line.startswith("## "):
            document.add_heading(line[3:], level=1)
        elif line.startswith("### "):
            document.add_heading(line[4:], level=2)
        elif line.startswith("- "):
            paragraph = document.add_paragraph(style="List Bullet")
            add_inline(paragraph, line[2:])
        else:
            paragraph = document.add_paragraph()
            add_inline(paragraph, line)
        count += 1

    footer = section.footer.paragraphs[0]
    add_page_number(footer)
    document.save(TARGET)

    with ZipFile(TARGET) as archive:
        assert archive.testzip() is None
        assert {"[Content_Types].xml", "word/document.xml", "word/styles.xml"} <= set(archive.namelist())

    reopened = Document(TARGET)
    paragraphs = [paragraph.text for paragraph in reopened.paragraphs if paragraph.text.strip()]
    assert len(paragraphs) == count
    assert paragraphs[0] == "mcp-guard 서비스 설명서"
    assert "15. 용어와 저장소 근거" in paragraphs
    assert any("MVP 11" in paragraph for paragraph in paragraphs)
    assert any("v14:" in paragraph for paragraph in paragraphs)
    return count, TARGET.stat().st_size


if __name__ == "__main__":
    paragraph_count, size = build()
    print(f"{TARGET} | {paragraph_count} paragraphs | {size} bytes | DOCX read-back validated")
