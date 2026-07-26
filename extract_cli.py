from __future__ import annotations

import argparse
import sys
from pathlib import Path

from extractor_core import ExtractionError, extract_pdf_from_exe


def main() -> int:
    parser = argparse.ArgumentParser(description="静态提取特定 PDF 封装 EXE 中的 PDF，不运行 EXE")
    parser.add_argument("inputs", nargs="+", help="一个或多个 EXE 文件")
    parser.add_argument("-o", "--output-dir", help="输出目录，默认与源文件相同")
    args = parser.parse_args()
    failures = 0
    for item in args.inputs:
        src = Path(item)
        out_dir = Path(args.output_dir) if args.output_dir else src.parent
        out = out_dir / f"{src.stem}_提取修复.pdf"
        print(f"\n=== {src.name} ===")
        try:
            result = extract_pdf_from_exe(src, out, log=print)
            print(f"成功：{result.output_path}")
            if result.warnings:
                print("警告：")
                for w in result.warnings:
                    print(" -", w)
        except (OSError, ExtractionError) as exc:
            failures += 1
            print(f"失败：{exc}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
