#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Word文档解析工具
支持提取文本、图片和嵌入文件
"""

import os
import sys
import zipfile
import shutil
from pathlib import Path

def extract_docx(docx_path, output_dir=None):
    """
    解析Word文档，提取文本、图片和嵌入文件

    Args:
        docx_path: Word文档路径
        output_dir: 输出目录（可选）
    """
    docx_path = Path(docx_path)

    if not docx_path.exists():
        print(f"错误: 文件不存在 - {docx_path}")
        return

    if docx_path.suffix.lower() not in ['.docx', '.docm']:
        print(f"警告: 文件可能不是标准的docx格式 - {docx_path.suffix}")

    # 设置输出目录
    if output_dir is None:
        output_dir = docx_path.parent / f"{docx_path.stem}_extracted"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"=" * 60)
    print(f"解析文件: {docx_path}")
    print(f"输出目录: {output_dir}")
    print(f"=" * 60)

    # 创建子目录
    media_dir = output_dir / "media"  # 图片
    embeddings_dir = output_dir / "embeddings"  # 嵌入文件
    xml_dir = output_dir / "xml"  # XML源文件

    media_dir.mkdir(exist_ok=True)
    embeddings_dir.mkdir(exist_ok=True)
    xml_dir.mkdir(exist_ok=True)

    # docx实际上是一个zip文件
    try:
        with zipfile.ZipFile(docx_path, 'r') as zip_ref:
            # 列出所有文件
            print("\n【文档结构】")
            for name in zip_ref.namelist():
                print(f"  {name}")

            # 提取所有文件
            zip_ref.extractall(output_dir / "temp_extract")

            # 提取文档文本内容
            document_xml = output_dir / "temp_extract" / "word" / "document.xml"
            if document_xml.exists():
                # 复制document.xml供查看
                shutil.copy2(document_xml, xml_dir / "document.xml")
                print(f"\n[成功] 文档XML已保存到: {xml_dir / 'document.xml'}")

            # 提取图片
            word_media = output_dir / "temp_extract" / "word" / "media"
            if word_media.exists():
                image_files = list(word_media.iterdir())
                if image_files:
                    print(f"\n【发现 {len(image_files)} 个图片文件】")
                    for img in image_files:
                        shutil.copy2(img, media_dir / img.name)
                        print(f"  [图片] {img.name}")
                else:
                    print("\n【无图片文件】")

            # 提取嵌入文件
            word_embeddings = output_dir / "temp_extract" / "word" / "embeddings"
            if word_embeddings.exists():
                embed_files = list(word_embeddings.iterdir())
                if embed_files:
                    print(f"\n【发现 {len(embed_files)} 个嵌入文件】")
                    for emb in embed_files:
                        shutil.copy2(emb, embeddings_dir / emb.name)
                        print(f"  [嵌入] {emb.name}")
                else:
                    print("\n【无嵌入文件】")

            # 提取rels关系文件（用于查找文件关联）
            rels_dir = output_dir / "temp_extract" / "word" / "_rels"
            if rels_dir.exists():
                for rels_file in rels_dir.iterdir():
                    shutil.copy2(rels_file, xml_dir / rels_file.name)

        # 尝试解析文本内容（简单方式）
        try:
            from xml.etree import ElementTree as ET

            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}

            if document_xml.exists():
                tree = ET.parse(document_xml)
                root = tree.getroot()

                # 提取所有文本段落
                texts = []
                for paragraph in root.findall('.//w:p', ns):
                    para_text = []
                    for node in paragraph.findall('.//w:t', ns):
                        if node.text:
                            para_text.append(node.text)
                    if para_text:
                        texts.append(''.join(para_text))

                # 保存文本内容
                text_file = output_dir / "extracted_text.txt"
                with open(text_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(texts))
                print(f"\n[成功] 文本内容已保存到: {text_file}")

                # 显示前2000字符
                preview_text = '\n'.join(texts)[:2000]
                print(f"\n【文本预览 (前2000字符)】")
                print("-" * 60)
                print(preview_text)
                if len('\n'.join(texts)) > 2000:
                    print("...")
                print("-" * 60)

        except Exception as e:
            print(f"\n解析文本时出错: {e}")

        # 清理临时文件
        shutil.rmtree(output_dir / "temp_extract", ignore_errors=True)

        print(f"\n" + "=" * 60)
        print(f"提取完成！输出目录: {output_dir}")
        print(f"=" * 60)

    except zipfile.BadZipFile:
        print(f"错误: 文件不是有效的docx格式（可能是一个旧的.doc文件）")
        print("提示: 请先将 .doc 文件转换为 .docx 格式")


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python read_word.py <docx文件路径> [输出目录]")
        print("示例: python read_word.py report.docx")
        print("示例: python read_word.py report.docx ./output")

        # 检查当前目录下是否有docx文件
        current_dir = Path(".")
        docx_files = list(current_dir.rglob("*.docx"))

        if docx_files:
            print(f"\n当前目录下发现以下docx文件:")
            for i, f in enumerate(docx_files, 1):
                print(f"  {i}. {f}")
            print("\n请使用: python read_word.py <文件路径>")
        else:
            print("\n当前目录下未发现docx文件")

        sys.exit(1)

    docx_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    extract_docx(docx_path, output_dir)


if __name__ == "__main__":
    main()
