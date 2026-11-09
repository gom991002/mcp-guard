"""Build the Korean service manual as a basic HWPX package (stdlib only).

The generated package is structurally checked here. It is not visually
round-tripped through Hancom Office, which is unavailable in this workspace.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "Docs" / "Core_mds" / "mcp-guard-서비스-설명서.md"
TARGET = ROOT / "Docs" / "Core_mds" / "mcp-guard-서비스-설명서.hwpx"
MIMETYPE = "application/hwp+zip"


def xml(text: str) -> str:
    return escape(text, {'"': "&quot;"})


def clean_md(text: str) -> str:
    text = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("**", "").replace("`", "")
    return text.strip()


def paragraphs(markdown: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    in_code = False
    for source_line in markdown.splitlines():
        line = source_line.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if not line:
            continue
        if in_code:
            result.append((4, source_line))
        elif line.startswith("### "):
            result.append((2, clean_md(line[4:])))
        elif line.startswith("## "):
            result.append((1, clean_md(line[3:])))
        elif line.startswith("# "):
            result.append((3, clean_md(line[2:])))
        elif line.startswith("- "):
            result.append((0, "• " + clean_md(line[2:])))
        else:
            result.append((0, clean_md(line)))
    return result


def make_section(items: list[tuple[int, str]]) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section" '
        'xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph">',
    ]
    for index, (style, value) in enumerate(items):
        lines.append(
            f'<hp:p id="{index}" paraPrIDRef="{1 if style else 0}" styleIDRef="0">'
            f'<hp:run charPrIDRef="{style}"><hp:t>{xml(value)}</hp:t></hp:run></hp:p>'
        )
    lines.append("</hs:sec>")
    return "\n".join(lines)


def build() -> tuple[int, int]:
    markdown = SOURCE.read_text(encoding="utf-8")
    items = paragraphs(markdown)
    assert items and items[0][1] == "mcp-guard 서비스 설명서"
    title = items[0][1]
    container = '''<?xml version="1.0" encoding="UTF-8"?>
<ocf:container xmlns:ocf="urn:oasis:names:tc:opendocument:xmlns:container">
<ocf:rootfiles><ocf:rootfile full-path="Contents/content.hpf" media-type="application/hwpml-package+xml"/></ocf:rootfiles>
</ocf:container>'''
    content = f'''<?xml version="1.0" encoding="UTF-8"?>
<opf:package xmlns:opf="http://www.idpf.org/2007/opf" xmlns:dc="http://purl.org/dc/elements/1.1/" version="1.0">
<opf:metadata><dc:title>{xml(title)}</dc:title><dc:creator>mcp-guard project</dc:creator>
<dc:date>2026-11-04</dc:date><dc:language>ko-KR</dc:language></opf:metadata>
<opf:manifest><opf:item id="header" href="header.xml" media-type="application/xml"/>
<opf:item id="section0" href="section0.xml" media-type="application/xml"/>
<opf:item id="settings" href="settings.xml" media-type="application/xml"/></opf:manifest>
<opf:spine><opf:itemref idref="section0"/></opf:spine></opf:package>'''
    header = '''<?xml version="1.0" encoding="UTF-8"?>
<hh:head xmlns:hh="http://www.hancom.co.kr/hwpml/2011/head">
<hh:beginNum page="1" footnote="1" endnote="1" pic="1" tbl="1" equation="1"/>
<hh:refList><hh:fontfaces><hh:fontface lang="HANGUL"><hh:font name="함초롬바탕" type="TTF"/></hh:fontface>
<hh:fontface lang="LATIN"><hh:font name="Arial" type="TTF"/></hh:fontface></hh:fontfaces>
<hh:borderFills><hh:borderFill id="0"/></hh:borderFills>
<hh:charProperties>
<hh:charPr id="0" height="950" textColor="#202020"/>
<hh:charPr id="1" height="1400" textColor="#15345D"><hh:bold/></hh:charPr>
<hh:charPr id="2" height="1150" textColor="#2B527D"><hh:bold/></hh:charPr>
<hh:charPr id="3" height="2000" textColor="#102C4C"><hh:bold/></hh:charPr>
<hh:charPr id="4" height="900" textColor="#333333"/>
</hh:charProperties>
<hh:paraProperties><hh:paraPr id="0" align="LEFT"/><hh:paraPr id="1" align="LEFT"/></hh:paraProperties>
<hh:styles><hh:style id="0" type="PARA" name="바탕글" paraPrIDRef="0" charPrIDRef="0"/></hh:styles>
<hh:bullets/><hh:numberings/></hh:refList></hh:head>'''
    files = {
        "version.xml": '''<?xml version="1.0" encoding="UTF-8"?>
<ha:HCFVersion xmlns:ha="http://www.hancom.co.kr/hwpml/2011/app" targetApplication="WORDPROC" major="5" minor="1" micro="0" buildNumber="0" os="Windows"/>''',
        "META-INF/container.xml": container,
        "Contents/content.hpf": content,
        "Contents/header.xml": header,
        "Contents/section0.xml": make_section(items),
        "Contents/settings.xml": '''<?xml version="1.0" encoding="UTF-8"?>
<ha:HWPApplicationSetting xmlns:ha="http://www.hancom.co.kr/hwpml/2011/app"/>''',
        "Preview/PrvText.txt": "\n".join(value for _, value in items),
    }
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(TARGET, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("mimetype", MIMETYPE, compress_type=ZIP_STORED)
        for path, data in files.items():
            archive.writestr(path, data.encode("utf-8"))
    with ZipFile(TARGET) as archive:
        names = archive.namelist()
        assert names[0] == "mimetype"
        assert archive.getinfo("mimetype").compress_type == ZIP_STORED
        assert archive.read("mimetype").decode("ascii") == MIMETYPE
        assert archive.testzip() is None
        for path in files:
            if path.endswith((".xml", ".hpf")):
                ET.fromstring(archive.read(path))
        section = ET.fromstring(archive.read("Contents/section0.xml"))
        text_nodes = section.findall(".//{http://www.hancom.co.kr/hwpml/2011/paragraph}t")
        assert len(text_nodes) == len(items)
        assert "Progress map" in archive.read("Preview/PrvText.txt").decode("utf-8")
    return len(items), TARGET.stat().st_size


if __name__ == "__main__":
    count, size = build()
    print(f"{TARGET} | {count} paragraphs | {size} bytes | ZIP/XML validated")
