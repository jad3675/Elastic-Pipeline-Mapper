import tkinter as tk
from tkinter import ttk, scrolledtext

class ResultsFrame(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Results", padding="10")
        
        self._setup_widgets()

    def _setup_widgets(self):
        button_frame = ttk.Frame(self)
        button_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.view_btn = ttk.Button(
            button_frame,
            text="View Diagram",
            state=tk.DISABLED
        )
        self.view_btn.grid(row=0, column=0, padx=5)
        
        text_frame = ttk.Frame(self)
        text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.results_text = scrolledtext.ScrolledText(
            text_frame,
            wrap=tk.WORD,
            width=80,
            height=20
        )
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

    def show_summary(self, summary):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, summary)
        self.view_btn.config(state=tk.NORMAL)