"""Tkinter desktop interface for ipasign.

The GUI is a thin shell around :func:`ipasign.bundle.sign_ipa`; all work runs
in a worker thread and reports back through a queue so the window stays
responsive while a large IPA is being signed.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from . import __version__
from .bundle import SignOptions, sign_ipa
from .pki import describe_chain, ensure_chain, load_identity
from .profile import ProvisioningProfile


class SigningApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"ipasign {__version__} - iOS IPA 签名工具")
        self.geometry("900x680")
        self.minsize(760, 560)
        self.queue: "queue.Queue[tuple]" = queue.Queue()
        self.worker: "threading.Thread | None" = None

        self.ipa_var = tk.StringVar()
        self.p12_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.profile_var = tk.StringVar()
        self.bundle_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.adhoc_var = tk.BooleanVar(value=False)
        self.download_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="就绪")

        self._build_ui()
        self.after(120, self._poll_queue)

    # -- layout ---------------------------------------------------------
    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        form = ttk.LabelFrame(outer, text="签名参数", padding=10)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        self._file_row(form, 0, "IPA 文件", self.ipa_var, self._pick_ipa, "打开")
        self._file_row(form, 1, "证书 p12", self.p12_var, self._pick_p12, "打开")
        self._file_row(form, 2, "描述文件", self.profile_var, self._pick_profile, "打开")

        ttk.Label(form, text="p12 密码").grid(row=3, column=0, sticky="w", pady=4)
        password_entry = ttk.Entry(form, textvariable=self.password_var, show="*")
        password_entry.grid(row=3, column=1, sticky="ew", padx=(8, 8), pady=4)

        ttk.Label(form, text="Bundle ID").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.bundle_var).grid(
            row=4, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Label(form, text="留空则沿用原值，并按描述文件自动校正").grid(
            row=4, column=2, sticky="w"
        )

        self._file_row(form, 5, "输出文件", self.output_var, self._pick_output, "另存为")

        options = ttk.Frame(form)
        options.grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))
        ttk.Checkbutton(
            options, text="仅 ad-hoc 签名（越狱设备）", variable=self.adhoc_var
        ).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(
            options, text="自动下载 Apple 中间证书", variable=self.download_var
        ).pack(side="left")

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=10)
        self.start_button = ttk.Button(actions, text="开始签名", command=self._start)
        self.start_button.pack(side="left")
        ttk.Button(actions, text="校验现有 IPA", command=self._verify).pack(
            side="left", padx=8
        )
        ttk.Button(actions, text="清空日志", command=self._clear_log).pack(side="left")
        ttk.Button(actions, text="打开输出目录", command=self._open_output_dir).pack(
            side="right"
        )

        log_frame = ttk.LabelFrame(outer, text="日志", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log_view = ScrolledText(
            log_frame, height=18, state="disabled", wrap="word",
            font=("Consolas", 9),
        )
        self.log_view.pack(fill="both", expand=True)

        ttk.Label(outer, textvariable=self.status_var, anchor="w").pack(fill="x", pady=(6, 0))

    def _file_row(self, parent, row, label, variable, command, button_text):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        ttk.Entry(parent, textvariable=variable).grid(
            row=row, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(parent, text=button_text, command=command, width=8).grid(
            row=row, column=2, pady=4
        )

    # -- file pickers ---------------------------------------------------
    def _pick_ipa(self) -> None:
        path = filedialog.askopenfilename(
            title="选择 IPA 文件", filetypes=[("iOS App", "*.ipa"), ("所有文件", "*.*")]
        )
        if path:
            self.ipa_var.set(path)
            if not self.output_var.get():
                source = Path(path)
                self.output_var.set(str(source.with_name(f"{source.stem}-signed.ipa")))

    def _pick_p12(self) -> None:
        path = filedialog.askopenfilename(
            title="选择签名证书",
            filetypes=[("PKCS#12", "*.p12 *.pfx"), ("所有文件", "*.*")],
        )
        if path:
            self.p12_var.set(path)

    def _pick_profile(self) -> None:
        path = filedialog.askopenfilename(
            title="选择描述文件",
            filetypes=[("Provisioning Profile", "*.mobileprovision"), ("所有文件", "*.*")],
        )
        if path:
            self.profile_var.set(path)

    def _pick_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="保存签名后的 IPA",
            defaultextension=".ipa",
            filetypes=[("iOS App", "*.ipa")],
            initialfile=Path(self.output_var.get()).name or "output.ipa",
        )
        if path:
            self.output_var.set(path)

    # -- logging --------------------------------------------------------
    def _log(self, message: str) -> None:
        self.queue.put(("log", message))

    def _append_log(self, message: str) -> None:
        self.log_view.configure(state="normal")
        self.log_view.insert("end", message.rstrip() + "\n")
        self.log_view.see("end")
        self.log_view.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_view.configure(state="normal")
        self.log_view.delete("1.0", "end")
        self.log_view.configure(state="disabled")

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "status":
                    self.status_var.set(str(payload))
                elif kind == "done":
                    self._on_done(payload)
                elif kind == "error":
                    self._on_error(str(payload))
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    # -- actions --------------------------------------------------------
    def _start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        ipa_path = self.ipa_var.get().strip()
        if not ipa_path or not Path(ipa_path).is_file():
            messagebox.showerror("提示", "请选择有效的 IPA 文件")
            return
        output = self.output_var.get().strip() or str(
            Path(ipa_path).with_name(Path(ipa_path).stem + "-signed.ipa")
        )
        ad_hoc = self.adhoc_var.get()
        if not ad_hoc:
            if not self.p12_var.get().strip():
                messagebox.showerror("提示", "请选择签名证书 p12")
                return
            if not self.profile_var.get().strip():
                messagebox.showerror("提示", "请选择描述文件")
                return

        self._clear_log()
        self.start_button.configure(state="disabled")
        self.status_var.set("签名中 ...")
        self.worker = threading.Thread(
            target=self._run,
            args=(ipa_path, output, ad_hoc),
            daemon=True,
        )
        self.worker.start()

    def _run(self, ipa_path: str, output: str, ad_hoc: bool) -> None:
        try:
            identity = None
            profile = None
            if not ad_hoc:
                self._log(f"读取描述文件: {self.profile_var.get()}")
                profile = ProvisioningProfile.load(self.profile_var.get())
                expiry = profile.expiration.strftime("%Y-%m-%d") if profile.expiration else "未知"
                self._log(
                    f"  {profile.name} / {profile.application_identifier} / 到期 {expiry}"
                )
                self._log(f"读取证书: {self.p12_var.get()}")
                identity = load_identity(self.p12_var.get(), self.password_var.get() or None)
                self._log(f"  {identity.common_name} (team {identity.team_id})")
                identity = ensure_chain(
                    identity,
                    allow_download=self.download_var.get(),
                    log=self._log,
                )
                for item in describe_chain(identity):
                    self._log(f"  链[{item['index']}] {item['subject']}")
                if not profile.has_certificate(identity.leaf):
                    self._log("[警告] 该证书不在描述文件的证书列表中，安装会被拒绝")

            options = SignOptions(bundle_id=self.bundle_var.get().strip() or None)
            report = sign_ipa(
                ipa_path,
                output,
                identity=identity,
                profile=profile,
                options=options,
                log=self._log,
            )
            self.queue.put(("done", (report, output)))
        except Exception as exc:  # noqa: BLE001 - surfaced in the dialog
            self._log(traceback.format_exc())
            self.queue.put(("error", str(exc)))

    def _on_done(self, payload) -> None:
        report, output = payload
        self.start_button.configure(state="normal")
        self.status_var.set(f"完成: {output}")
        for warning in report.warnings:
            self._log(f"[警告] {warning}")
        self._log(f"[完成] 输出: {output}")
        messagebox.showinfo(
            "签名完成",
            f"输出文件:\n{output}\n\nBundle ID: {report.bundle_id}\n"
            f"已签名 {len(report.steps)} 个 Mach-O 文件",
        )

    def _on_error(self, message: str) -> None:
        self.start_button.configure(state="normal")
        self.status_var.set("失败")
        messagebox.showerror("签名失败", message)

    def _verify(self) -> None:
        ipa_path = self.ipa_var.get().strip()
        if not ipa_path:
            messagebox.showerror("提示", "请先选择 IPA 文件")
            return
        from .verify import verify_ipa

        try:
            report = verify_ipa(ipa_path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("校验失败", str(exc))
            return
        self._clear_log()
        for check in report.checks:
            status = "OK " if not check.problems else "ERR"
            self._log(f"[{status}] {check.path}  {check.identifier}")
            for problem in check.problems:
                self._log(f"      - {problem}")
        if report.ok:
            messagebox.showinfo("校验结果", "签名结构校验通过")
        else:
            messagebox.showwarning("校验结果", "发现问题：" + "\n".join(report.all_problems()[:10]))

    def _open_output_dir(self) -> None:
        import subprocess
        import sys

        target = Path(self.output_var.get() or self.ipa_var.get() or ".")
        directory = target.parent if target.parent.exists() else Path.cwd()
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", str(directory)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(directory)])
            else:
                subprocess.Popen(["xdg-open", str(directory)])
        except OSError:
            pass


def main() -> int:
    app = SigningApp()
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
