from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import traceback
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from extractor_core import ExtractionError, extract_pdf_from_exe


APP_TITLE = "PDF 封装 EXE 静态提取工具"


class ExtractorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x650")
        self.minsize(760, 540)
        self.files: list[Path] = []
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.running = False

        self.output_var = tk.StringVar(value=str(Path.home() / "Desktop"))
        self.status_var = tk.StringVar(value="请选择一个或多个 EXE 文件")
        self._build_ui()
        self._load_command_line_files()
        self.after(100, self._poll_events)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=14)
        outer.pack(fill="both", expand=True)

        title = ttk.Label(outer, text=APP_TITLE, font=("Microsoft YaHei UI", 17, "bold"))
        title.pack(anchor="w")
        subtitle = ttk.Label(
            outer,
            text="只读取 EXE 字节，不启动或运行 EXE；支持批量提取、结构修复和日志记录。",
        )
        subtitle.pack(anchor="w", pady=(4, 12))

        file_box = ttk.LabelFrame(outer, text="待处理文件", padding=10)
        file_box.pack(fill="both", expand=False)

        list_frame = ttk.Frame(file_box)
        list_frame.pack(fill="both", expand=True)
        self.file_list = tk.Listbox(list_frame, height=9, selectmode=tk.EXTENDED)
        self.file_list.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_list.yview)
        scrollbar.pack(side="right", fill="y")
        self.file_list.configure(yscrollcommand=scrollbar.set)

        btns = ttk.Frame(file_box)
        btns.pack(fill="x", pady=(8, 0))
        ttk.Button(btns, text="选择 EXE…", command=self._choose_files).pack(side="left")
        ttk.Button(btns, text="移除选中", command=self._remove_selected).pack(side="left", padx=8)
        ttk.Button(btns, text="清空", command=self._clear_files).pack(side="left")

        output_box = ttk.LabelFrame(outer, text="输出目录", padding=10)
        output_box.pack(fill="x", pady=12)
        ttk.Entry(output_box, textvariable=self.output_var).pack(side="left", fill="x", expand=True)
        ttk.Button(output_box, text="浏览…", command=self._choose_output).pack(side="left", padx=(8, 0))
        ttk.Button(output_box, text="打开目录", command=self._open_output).pack(side="left", padx=(8, 0))

        action = ttk.Frame(outer)
        action.pack(fill="x")
        self.start_button = ttk.Button(action, text="开始静态提取", command=self._start)
        self.start_button.pack(side="left")
        self.progress = ttk.Progressbar(action, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True, padx=12)
        ttk.Label(action, textvariable=self.status_var).pack(side="right")

        log_box = ttk.LabelFrame(outer, text="处理日志", padding=8)
        log_box.pack(fill="both", expand=True, pady=(12, 0))
        self.log = tk.Text(log_box, wrap="word", height=14, state="disabled")
        self.log.pack(side="left", fill="both", expand=True)
        log_scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log.yview)
        log_scroll.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=log_scroll.set)


    def _load_command_line_files(self) -> None:
        initial: list[Path] = []
        for arg in sys.argv[1:]:
            path = Path(arg).expanduser()
            if path.is_file() and path.suffix.lower() == ".exe":
                initial.append(path.resolve())
        for path in initial:
            if path not in self.files:
                self.files.append(path)
                self.file_list.insert(tk.END, str(path))
        if initial:
            self.output_var.set(str(initial[0].parent))
            self.status_var.set(f"已载入 {len(initial)} 个文件")

    def _choose_files(self) -> None:
        names = filedialog.askopenfilenames(
            title="选择含 PDF 的 EXE 文件",
            filetypes=[("Windows EXE", "*.exe"), ("所有文件", "*.*")],
        )
        for name in names:
            path = Path(name)
            if path not in self.files:
                self.files.append(path)
                self.file_list.insert(tk.END, str(path))
        if self.files:
            self.status_var.set(f"已选择 {len(self.files)} 个文件")

    def _remove_selected(self) -> None:
        indices = list(self.file_list.curselection())
        for index in reversed(indices):
            self.file_list.delete(index)
            del self.files[index]
        self.status_var.set(f"已选择 {len(self.files)} 个文件")

    def _clear_files(self) -> None:
        self.files.clear()
        self.file_list.delete(0, tk.END)
        self.status_var.set("请选择一个或多个 EXE 文件")

    def _choose_output(self) -> None:
        name = filedialog.askdirectory(title="选择 PDF 输出目录", initialdir=self.output_var.get())
        if name:
            self.output_var.set(name)

    def _open_output(self) -> None:
        path = Path(self.output_var.get()).expanduser()
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except OSError as exc:
            messagebox.showerror("无法打开目录", str(exc))

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert(tk.END, text.rstrip() + "\n")
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    def _start(self) -> None:
        if self.running:
            return
        if not self.files:
            messagebox.showwarning("未选择文件", "请先选择至少一个 EXE 文件。")
            return
        out_dir = Path(self.output_var.get()).expanduser()
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("输出目录不可用", str(exc))
            return

        self.running = True
        self.start_button.configure(state="disabled")
        self.progress.configure(maximum=len(self.files), value=0)
        self.status_var.set("正在提取…")
        self._append_log("=" * 66)
        self._append_log("开始处理。安全模式：不会执行任何 EXE。")
        worker = threading.Thread(target=self._worker, args=(list(self.files), out_dir), daemon=True)
        worker.start()

    def _worker(self, files: list[Path], out_dir: Path) -> None:
        successes = 0
        for index, src in enumerate(files, start=1):
            self.events.put(("log", f"\n[{index}/{len(files)}] {src.name}"))
            out = out_dir / f"{src.stem}_提取修复.pdf"
            try:
                result = extract_pdf_from_exe(
                    src,
                    out,
                    log=lambda text: self.events.put(("log", "  " + text)),
                )
                successes += 1
                self.events.put(("log", f"  成功：{result.output_path}"))
                if result.page_hint is not None:
                    self.events.put(("log", f"  页数：{result.page_hint}"))
                for warning in result.warnings:
                    self.events.put(("log", f"  警告：{warning}"))
            except (OSError, ExtractionError) as exc:
                self.events.put(("log", f"  失败：{exc}"))
            except Exception:
                self.events.put(("log", "  未预期错误：\n" + traceback.format_exc()))
            self.events.put(("progress", index))
        self.events.put(("done", (successes, len(files), out_dir)))

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "progress":
                    self.progress.configure(value=int(payload))
                elif kind == "done":
                    successes, total, out_dir = payload  # type: ignore[misc]
                    self.running = False
                    self.start_button.configure(state="normal")
                    self.status_var.set(f"完成：{successes}/{total} 成功")
                    self._append_log(f"\n处理结束：{successes}/{total} 成功。输出目录：{out_dir}")
                    if successes == total:
                        messagebox.showinfo("提取完成", f"已成功处理 {successes} 个文件。")
                    else:
                        messagebox.showwarning("处理完成", f"成功 {successes} 个，失败 {total - successes} 个；请查看日志。")
        except queue.Empty:
            pass
        self.after(100, self._poll_events)


if __name__ == "__main__":
    ExtractorApp().mainloop()
