import tkinter as tk
from tkinter import ttk, Listbox, MULTIPLE

class AnalysisFrame(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Analysis Options", padding="10")
        
        self.analysis_type = tk.StringVar(value="index")
        self.visualization_level = tk.StringVar(value="overview")
        self.search_var = tk.StringVar()
        
        self._setup_widgets()

    def _setup_widgets(self):
        # Start Analysis From section
        ttk.Label(self, text="Start Analysis From:").grid(row=0, column=0, sticky=tk.W)
        
        self.index_rb = ttk.Radiobutton(
            self,
            text="Index",
            variable=self.analysis_type,
            value="index"
        )
        self.index_rb.grid(row=0, column=1)
        
        self.pipeline_rb = ttk.Radiobutton(
            self,
            text="Pipeline",
            variable=self.analysis_type,
            value="pipeline"
        )
        self.pipeline_rb.grid(row=0, column=2)
        
        self.enrich_rb = ttk.Radiobutton(
            self,
            text="Enrichment Policy",
            variable=self.analysis_type,
            value="enrich"
        )
        self.enrich_rb.grid(row=0, column=3)
        
        self.index_template_rb = ttk.Radiobutton(
            self,
            text="Index Template",
            variable=self.analysis_type,
            value="index_template"
        )
        self.index_template_rb.grid(row=1, column=1)
        
        self.component_template_rb = ttk.Radiobutton(
            self,
            text="Component Template",
            variable=self.analysis_type,
            value="component_template"
        )
        self.component_template_rb.grid(row=1, column=2)

        self.transform_rb = ttk.Radiobutton(
            self,
            text="Transform",
            variable=self.analysis_type,
            value="transform"
        )
        self.transform_rb.grid(row=1, column=3)
        
        # Visualization Level Selection
        ttk.Separator(self, orient='horizontal').grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(self, text="Visualization Level:").grid(row=3, column=0, sticky=tk.W)
        
        level_frame = ttk.Frame(self)
        level_frame.grid(row=2, column=1, columnspan=3, sticky=tk.W)
        
        ttk.Radiobutton(
            level_frame,
            text="📊 Overview",
            variable=self.visualization_level,
            value="overview"
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        ttk.Radiobutton(
            level_frame,
            text="🔧 Pipeline Detail",
            variable=self.visualization_level,
            value="pipeline_detail"
        ).grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
        ttk.Radiobutton(
            level_frame,
            text="🔬 Processor Detail",
            variable=self.visualization_level,
            value="processor_detail"
        ).grid(row=0, column=2, sticky=tk.W)
        
        # Level descriptions
        level_desc_frame = ttk.Frame(self)
        level_desc_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        level_descriptions = ttk.Label(
            level_desc_frame,
            text="📊 Overview: High-level pipeline relationships | 🔧 Pipeline Detail: Logical processing phases | 🔬 Processor Detail: Detailed processor groups",
            font=("TkDefaultFont", 8),
            foreground="gray"
        )
        level_descriptions.grid(row=0, column=0, sticky=tk.W)
        
        # Search and selection section
        search_frame = ttk.Frame(self)
        search_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 5))
        self.search_var.trace('w', self.filter_selection_list)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=50)
        search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        list_frame = ttk.Frame(self)
        list_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E))
        
        self.selection_list = Listbox(list_frame, selectmode=MULTIPLE, height=6)
        self.selection_list.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.selection_list.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.selection_list.configure(yscrollcommand=scrollbar.set)
        
        list_frame.columnconfigure(0, weight=1)
        
        self.analyze_btn = ttk.Button(
            self,
            text="Analyze",
            state=tk.DISABLED
        )
        self.analyze_btn.grid(row=6, column=0, columnspan=4, pady=10)

    def get_analysis_options(self):
        selected_indices = self.selection_list.curselection()
        selected_items = [self.selection_list.get(i) for i in selected_indices]
        return {
            "analysis_type": self.analysis_type.get(),
            "visualization_level": self.visualization_level.get(),
            "selected_items": selected_items
        }

    def update_selection_list(self, items):
        self._all_items = items
        self.selection_list.delete(0, tk.END)
        for item in items:
            self.selection_list.insert(tk.END, item)

    def filter_selection_list(self, *args):
        search_text = self.search_var.get().lower()
        
        self.selection_list.delete(0, tk.END)
        
        if not hasattr(self, '_all_items'):
            return

        if search_text:
            items = [item for item in self._all_items if search_text in item.lower()]
            for item in items:
                self.selection_list.insert(tk.END, item)
        else:
            for item in self._all_items:
                self.selection_list.insert(tk.END, item)