import tkinter as tk
from tkinter import ttk
from .credentials_frame import CredentialsFrame
from .analysis_frame import AnalysisFrame
from .results_frame import ResultsFrame

class MainFrame(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding="10")
        self.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.credentials_frame = CredentialsFrame(self)
        self.analysis_frame = AnalysisFrame(self)
        self.results_frame = ResultsFrame(self)
        
        self.credentials_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        self.analysis_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        self.results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)