import time
import tkinter as tk
from tkinter import ttk, messagebox

import lab


class AESDesktopUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AES-128 Desktop Encrypt/Decrypt")
        self.root.geometry("760x460")
        self.root.minsize(700, 420)
        self.root.configure(bg="#f4f6f8")

        self.default_placeholder = "Nhập đúng 15 ký tự..."
        self.key_text = "CSATBMTT_AESKEY!"  # 16-byte key cho AES-128

        self._setup_style()
        self._build_layout()

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Main.TFrame", background="#f4f6f8")
        style.configure("Card.TLabelframe", background="#ffffff")
        style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"))
        style.configure("TLabel", background="#f4f6f8", font=("Segoe UI", 10))
        style.configure("Result.TLabel", background="#ffffff", font=("Consolas", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"))

    def _build_layout(self):
        container = ttk.Frame(self.root, style="Main.TFrame", padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(
            container,
            text="AES-128 Encryption Timing",
            font=("Segoe UI", 18, "bold"),
            background="#f4f6f8",
        )
        title.pack(anchor=tk.W)

        subtitle = ttk.Label(
            container,
            text="Nhập chuỗi 15 ký tự, bấm Mã hóa/Giải mã để xem kết quả và thời gian.",
        )
        subtitle.pack(anchor=tk.W, pady=(4, 16))

        input_card = ttk.LabelFrame(container, text="Dữ liệu đầu vào", style="Card.TLabelframe", padding=16)
        input_card.pack(fill=tk.X)

        input_card.columnconfigure(1, weight=1)

        ttk.Label(input_card, text="Plain text (15 ký tự):", background="#ffffff").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 10), pady=(0, 8)
        )

        self.input_var = tk.StringVar()
        self.input_entry = ttk.Entry(input_card, textvariable=self.input_var, width=56)
        self.input_entry.grid(row=0, column=1, sticky=tk.EW, pady=(0, 8))

        self.char_count_label = ttk.Label(input_card, text="0/15", background="#ffffff")
        self.char_count_label.grid(row=1, column=1, sticky=tk.W)

        button_frame = ttk.Frame(input_card, style="Main.TFrame")
        button_frame.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(14, 0))

        ttk.Button(button_frame, text="Mã hóa + Giải mã", command=self.process).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Xóa", command=self.clear_all).pack(side=tk.LEFT, padx=(10, 0))

        output_card = ttk.LabelFrame(container, text="Kết quả", style="Card.TLabelframe", padding=16)
        output_card.pack(fill=tk.BOTH, expand=True, pady=(16, 0))
        output_card.columnconfigure(1, weight=1)

        ttk.Label(output_card, text="Chuỗi mã hóa (hex):", style="Result.TLabel").grid(
            row=0, column=0, sticky=tk.NW, padx=(0, 10), pady=(0, 10)
        )
        self.cipher_value = ttk.Label(output_card, text="-", style="Result.TLabel", wraplength=500, justify=tk.LEFT)
        self.cipher_value.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(output_card, text="Chuỗi giải mã:", style="Result.TLabel").grid(
            row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(0, 10)
        )
        self.plain_value = ttk.Label(output_card, text="-", style="Result.TLabel")
        self.plain_value.grid(row=1, column=1, sticky=tk.W)

        ttk.Label(output_card, text="Thời gian mã hóa:", style="Result.TLabel").grid(
            row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(0, 8)
        )
        self.encrypt_time_value = ttk.Label(output_card, text="-", style="Result.TLabel")
        self.encrypt_time_value.grid(row=2, column=1, sticky=tk.W)

        ttk.Label(output_card, text="Thời gian giải mã:", style="Result.TLabel").grid(
            row=3, column=0, sticky=tk.W, padx=(0, 10)
        )
        self.decrypt_time_value = ttk.Label(output_card, text="-", style="Result.TLabel")
        self.decrypt_time_value.grid(row=3, column=1, sticky=tk.W)

        self._set_placeholder()
        self.input_entry.bind("<FocusIn>", self._on_focus_in)
        self.input_entry.bind("<FocusOut>", self._on_focus_out)
        self.input_var.trace_add("write", self._update_char_count)

    def _set_placeholder(self):
        self.input_var.set(self.default_placeholder)
        self.input_entry.configure(foreground="#7a7a7a")

    def _on_focus_in(self, _event):
        if self.input_var.get() == self.default_placeholder:
            self.input_var.set("")
            self.input_entry.configure(foreground="#111111")

    def _on_focus_out(self, _event):
        if not self.input_var.get().strip():
            self._set_placeholder()

    def _current_input(self):
        text = self.input_var.get()
        if text == self.default_placeholder:
            return ""
        return text

    def _update_char_count(self, *_args):
        length = len(self._current_input())
        self.char_count_label.config(text=f"{length}/15")

    def process(self):
        user_input = self._current_input().strip()

        if len(user_input) != 15:
            messagebox.showwarning("ảnh báo", "Vui lòng nhập đúng 15 ký tự.")
            return

        try:
            plain_bytes = lab.text_to_bytes(user_input)
            key_bytes = lab.text_to_bytes(self.key_text)

            t1 = time.perf_counter()
            cipher_bytes = lab.aes_encrypt_ecb(plain_bytes, key_bytes)
            t2 = time.perf_counter()

            t3 = time.perf_counter()
            recovered_bytes = lab.aes_decrypt_ecb(cipher_bytes, key_bytes)
            t4 = time.perf_counter()

            cipher_hex = lab.bytes_to_hex(cipher_bytes)
            recovered_text = lab.bytes_to_text(recovered_bytes)

            self.cipher_value.config(text=cipher_hex)
            self.plain_value.config(text=recovered_text)
            self.encrypt_time_value.config(text=f"{(t2 - t1) * 1000:.6f} ms")
            self.decrypt_time_value.config(text=f"{(t4 - t3) * 1000:.6f} ms")
        except Exception as exc:
            messagebox.showerror("Lỗi", f"Không thể xử lý dữ liệu: {exc}")

    def clear_all(self):
        self._set_placeholder()
        self.cipher_value.config(text="-")
        self.plain_value.config(text="-")
        self.encrypt_time_value.config(text="-")
        self.decrypt_time_value.config(text="-")


if __name__ == "__main__":
    app_root = tk.Tk()
    AESDesktopUI(app_root)
    app_root.mainloop()
