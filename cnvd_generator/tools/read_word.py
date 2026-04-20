#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Word 解析工具：提取文本、图片和嵌入文件。"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional


def extract_docx(docx_path: str | Path, output_dir: str | Path | None = None) -> Dict[str, Any]:
    """
    解析 docx/docm 文件并输出结构化提取结果。

    Returns:
        {
          "output_dir": "...",
          "text_path": "...",
          "xml_path": "...",
          "media_files": [...],
          "embedding_files": [...],
          "text": "..."
        }
    """
    source = Path(docx_path)
    if not source.exists():
        raise FileNotFoundError(f"Word文件不存在: {source}")
    if source.suffix.lower() not in (".docx", ".docm"):
        raise ValueError(f"不支持的文件格式: {source.suffix}")

    target_dir = Path(output_dir) if output_dir else source.parent / f"{source.stem}_extracted"
    target_dir.mkdir(parents=True, exist_ok=True)

    media_dir = target_dir / "media"
    embeddings_dir = target_dir / "embeddings"
    xml_dir = target_dir / "xml"
    media_dir.mkdir(exist_ok=True)
    embeddings_dir.mkdir(exist_ok=True)
    xml_dir.mkdir(exist_ok=True)

    temp_extract = target_dir / "temp_extract"
    if temp_extract.exists():
        shutil.rmtree(temp_extract, ignore_errors=True)

    media_files: List[str] = []
    embedding_files: List[str] = []
    extracted_text = ""
    text_path = target_dir / "extracted_text.txt"
    xml_path = xml_dir / "document.xml"

    try:
        with zipfile.ZipFile(source, "r") as zip_ref:
            zip_ref.extractall(temp_extract)

        document_xml = temp_extract / "word" / "document.xml"
        if document_xml.exists():
            shutil.copy2(document_xml, xml_path)
            extracted_text = _parse_document_xml(document_xml)
            text_path.write_text(extracted_text, encoding="utf-8", errors="replace")

        word_media = temp_extract / "word" / "media"
        if word_media.exists():
            for img in sorted(word_media.iterdir(), key=lambda p: p.name.lower()):
                if not img.is_file():
                    continue
                dst = media_dir / img.name
                shutil.copy2(img, dst)
                media_files.append(str(dst))

        word_embeddings = temp_extract / "word" / "embeddings"
        if word_embeddings.exists():
            for emb in sorted(word_embeddings.iterdir(), key=lambda p: p.name.lower()):
                if not emb.is_file():
                    continue
                dst = embeddings_dir / emb.name
                shutil.copy2(emb, dst)
                embedding_files.append(str(dst))

        rels_dir = temp_extract / "word" / "_rels"
        if rels_dir.exists():
            for rels_file in rels_dir.iterdir():
                if rels_file.is_file():
                    shutil.copy2(rels_file, xml_dir / rels_file.name)
    except zipfile.BadZipFile as error:
        raise RuntimeError(f"无效的 docx 文件: {source}") from error
    finally:
        shutil.rmtree(temp_extract, ignore_errors=True)

    return {
        "output_dir": str(target_dir),
        "text_path": str(text_path) if text_path.exists() else "",
        "xml_path": str(xml_path) if xml_path.exists() else "",
        "media_files": media_files,
        "embedding_files": embedding_files,
        "text": extracted_text,
    }


def _parse_document_xml(xml_path: Path) -> str:
    from xml.etree import ElementTree as ET

    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    tree = ET.parse(xml_path)
    root = tree.getroot()

    texts: List[str] = []
    for paragraph in root.findall(".//w:p", ns):
        para_text: List[str] = []
        for node in paragraph.findall(".//w:t", ns):
            if node.text:
                para_text.append(node.text)
        if para_text:
            texts.append("".join(para_text))
    return "\n".join(texts)


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract text/media from docx/docm")
    parser.add_argument("docx_path")
    parser.add_argument("output_dir", nargs="?")
    args = parser.parse_args(argv)

    result = extract_docx(args.docx_path, args.output_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

