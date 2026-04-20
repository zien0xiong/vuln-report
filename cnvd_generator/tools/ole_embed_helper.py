#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在交互会话中为 Word 报告补插 OLE 漏洞代码对象。"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List


def _find_text_range(doc: Any, text: str) -> Any:
    rng = doc.Content
    finder = rng.Find
    finder.ClearFormatting()
    finder.Text = str(text)
    finder.Forward = True
    finder.Wrap = 1
    if finder.Execute():
        return rng.Duplicate
    return None


def _insert_single_ole(doc: Any, item: Dict[str, str]) -> bool:
    source_path = str(item.get("source_path", "") or "").strip()
    if not source_path:
        return False
    file_path = Path(source_path)
    if not file_path.exists():
        return False

    icon_label = str(item.get("display_name", "") or file_path.name)
    original_path = str(item.get("original_path", "") or "").strip()

    target_range = None
    for target_text in [original_path, file_path.name]:
        if target_text:
            target_range = _find_text_range(doc, target_text)
            if target_range is not None:
                break

    if target_range is None:
        target_range = _find_text_range(doc, "存在漏洞的代码文件")
        if target_range is None:
            target_range = doc.Content

    insert_range = target_range.Duplicate
    insert_range.Collapse(0)
    insert_range.InsertParagraphAfter()
    insert_range.Collapse(0)
    doc.InlineShapes.AddOLEObject(
        ClassType=None,
        FileName=str(file_path.resolve()),
        LinkToFile=False,
        DisplayAsIcon=True,
        IconFileName=None,
        IconIndex=0,
        IconLabel=icon_label,
        Range=insert_range,
    )
    tail = doc.Range(insert_range.End, insert_range.End)
    tail.InsertParagraphAfter()
    return True


def _clear_existing_ole_objects(doc: Any) -> None:
    try:
        count = int(doc.InlineShapes.Count)
        for idx in range(count, 0, -1):
            shape = doc.InlineShapes(idx)
            shape_type = int(getattr(shape, "Type", 0))
            if shape_type in (1, 2):
                shape.Delete()
    except Exception:
        pass


def run(payload_path: Path, result_path: Path) -> int:
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    doc_path = Path(str(payload.get("doc_path", "") or ""))
    file_objects = payload.get("file_objects", [])
    if not isinstance(file_objects, list):
        file_objects = []

    if not doc_path.exists():
        result_path.write_text(
            json.dumps({"success": False, "error": f"doc not found: {doc_path}"}, ensure_ascii=False),
            encoding="utf-8",
        )
        return 2

    try:
        import pythoncom  # type: ignore
        import win32com.client  # type: ignore
    except Exception as error:
        result_path.write_text(
            json.dumps({"success": False, "error": f"pywin32 import failed: {error}"}, ensure_ascii=False),
            encoding="utf-8",
        )
        return 3

    inserted = 0
    word = None
    doc = None
    try:
        pythoncom.CoInitialize()
        word = win32com.client.DispatchEx("Word.Application")
        word.Visible = False
        word.DisplayAlerts = 0
        doc = word.Documents.Open(str(doc_path.resolve()))

        _clear_existing_ole_objects(doc)
        for item in file_objects:
            if isinstance(item, dict) and _insert_single_ole(doc, item):
                inserted += 1

        doc.Save()
        result = {"success": inserted > 0, "inserted": inserted, "error": ""}
        result_path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        return 0
    except Exception as error:
        result = {"success": False, "inserted": inserted, "error": str(error)}
        result_path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        return 4
    finally:
        try:
            if doc is not None:
                doc.Close(False)
        except Exception:
            pass
        try:
            if word is not None:
                word.Quit()
        except Exception:
            pass
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    return run(Path(args.payload), Path(args.result))


if __name__ == "__main__":
    raise SystemExit(main())
