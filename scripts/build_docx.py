#!/usr/bin/env python3
"""把 docs/ 下的 Markdown 文档批量转成符合「合工大书写格式」的 Word(.docx)。

流程：
1. 用 pandoc 取默认 reference.docx，打补丁成合工大样式（正文宋体小四 1.5 倍行距、
   标题黑体黑色、A4 + 上2.5/下2/左2.5/右2cm 页边距）。
2. 预处理每个 md（课程报告的 \\newpage → 真正的 docx 分页符）。
3. pandoc 转换，图片相对路径以 docs/ 为 resource-path 解析。

用法：python scripts/build_docx.py
依赖：pandoc。安装见 docs/uml/README.md。
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "out"
REF = OUT / "_reference.docx"

# 待转换文档：(输入 md, 输出 docx)
DOCUMENTS = [
    ("软件杯-1-需求分析.md", "软件杯-1-需求分析.docx"),
    ("软件杯-2-功能设计.md", "软件杯-2-功能设计.docx"),
    ("软件杯-3-产品说明书.md", "软件杯-3-产品说明书.docx"),
    ("软件杯-4-功能测试报告.md", "软件杯-4-功能测试报告.docx"),
    ("软件杯-5-性能测试报告.md", "软件杯-5-性能测试报告.docx"),
    ("软件杯-8-演示PPT大纲.md", "软件杯-8-演示PPT大纲.docx"),
    ("课程报告.md", "课程报告.docx"),
]

# A4 + 合工大页边距（单位 twips，1cm≈567）
SECTPR = (
    '<w:sectPr>'
    '<w:pgSz w:w="11906" w:h="16838"/>'
    '<w:pgMar w:top="1417" w:right="1134" w:bottom="1134" w:left="1417" '
    'w:header="1134" w:footer="1134" w:gutter="0"/>'
    '<w:cols w:space="720"/><w:docGrid w:linePitch="360"/>'
    '</w:sectPr>'
)


def build_reference() -> None:
    """生成并打补丁出合工大样式的 reference.docx。"""
    OUT.mkdir(parents=True, exist_ok=True)
    base = OUT / "_ref_default.docx"
    with base.open("wb") as f:
        subprocess.run(["pandoc", "--print-default-data-file", "reference.docx"],
                       check=True, stdout=f)

    work = OUT / "_refwork"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    with zipfile.ZipFile(base) as z:
        z.extractall(work)

    styles = (work / "word/styles.xml").read_text(encoding="utf-8")
    # 1) 正文默认字体：英文 Times New Roman、中文宋体（eastAsia）
    styles = styles.replace(
        '<w:rFonts w:asciiTheme="minorHAnsi" w:eastAsiaTheme="minorHAnsi" '
        'w:hAnsiTheme="minorHAnsi" w:cstheme="minorBidi" />',
        '<w:rFonts w:ascii="Times New Roman" w:eastAsia="宋体" '
        'w:hAnsi="Times New Roman" w:cs="Times New Roman" />')
    # 2) 正文 1.5 倍行距（line=360 auto），段后 0
    styles = styles.replace(
        '<w:pPr>\n        <w:spacing w:after="200" />\n      </w:pPr>',
        '<w:pPr>\n        <w:spacing w:after="0" w:line="360" w:lineRule="auto" />\n      </w:pPr>')
    # 3) 各级标题：黑体、黑色（去掉默认蓝），全局替换（H1/H2/H3 的 rFonts/color 串一致）
    styles = styles.replace(
        '<w:rFonts w:asciiTheme="majorHAnsi" w:eastAsiaTheme="majorEastAsia" '
        'w:hAnsiTheme="majorHAnsi" w:cstheme="majorBidi" />',
        '<w:rFonts w:ascii="黑体" w:eastAsia="黑体" w:hAnsi="黑体" w:cs="黑体" />')
    styles = styles.replace('<w:color w:val="4F81BD" w:themeColor="accent1" />',
                            '<w:color w:val="000000" />')
    # 一级标题字号小三号(30 半磅)
    styles = styles.replace('<w:sz w:val="32" />\n      <w:szCs w:val="32" />',
                            '<w:sz w:val="30" />\n      <w:szCs w:val="30" />')
    (work / "word/styles.xml").write_text(styles, encoding="utf-8")

    # 4) 页面设置：在 body 末尾插入 A4 + 合工大页边距 sectPr
    doc = (work / "word/document.xml").read_text(encoding="utf-8")
    doc = re.sub(r'<w:sectPr.*?</w:sectPr>', '', doc, flags=re.S)  # 去掉已有
    doc = doc.replace('</w:body>', SECTPR + '</w:body>')
    (work / "word/document.xml").write_text(doc, encoding="utf-8")

    if REF.exists():
        REF.unlink()
    with zipfile.ZipFile(REF, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(work.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(work).as_posix())
    print(f"[ok] 合工大样式参考模板：{REF.relative_to(ROOT)}")


# docx 分页符（openxml 原生），供 \newpage 替换
PAGEBREAK = ('\n\n```{=openxml}\n<w:p><w:r><w:br w:type="page"/></w:r></w:p>\n```\n\n')


def preprocess(md_text: str) -> str:
    """\\newpage 行 → 真正的 docx 分页符。"""
    return re.sub(r'(?m)^\\newpage\s*$', PAGEBREAK, md_text)


def set_page(docx: Path) -> None:
    """后处理：把 A4 + 合工大页边距 sectPr 注入输出 docx（pandoc 默认不写页面设置）。"""
    import io
    with zipfile.ZipFile(docx) as z:
        items = {n: z.read(n) for n in z.namelist()}
    doc = items["word/document.xml"].decode("utf-8")
    doc = re.sub(r'<w:sectPr.*?</w:sectPr>', '', doc, flags=re.S)
    doc = doc.replace('</w:body>', SECTPR + '</w:body>')
    items["word/document.xml"] = doc.encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in items.items():
            z.writestr(n, data)
    docx.write_bytes(buf.getvalue())


def convert(src_name: str, out_name: str) -> None:
    src = DOCS / src_name
    if not src.exists():
        print(f"[skip] 不存在：{src_name}")
        return
    tmp = OUT / ("_pp_" + src_name)
    tmp.write_text(preprocess(src.read_text(encoding="utf-8")), encoding="utf-8")
    out = OUT / out_name
    subprocess.run([
        "pandoc", str(tmp), "-o", str(out),
        "--reference-doc", str(REF),
        "--resource-path", str(DOCS),
        "-f", "markdown+raw_html-tex_math_dollars-tex_math_single_backslash",
    ], check=True)
    tmp.unlink()
    set_page(out)
    print(f"[ok] {out.relative_to(ROOT)}  ({out.stat().st_size // 1024} KB)")


def main() -> int:
    build_reference()
    for src, out in DOCUMENTS:
        convert(src, out)
    print("\n全部完成 →", OUT.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
