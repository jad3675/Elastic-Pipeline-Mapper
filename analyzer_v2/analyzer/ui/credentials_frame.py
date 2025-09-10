import tkinter as tk
from tkinter import ttk

class CredentialsFrame(ttk.LabelFrame):
    def __init__(self, parent):
        super().__init__(parent, text="Elasticsearch Connection", padding="10")
        
        self.connection_type = tk.StringVar(value="cloud_id")
        self.auth_type = tk.StringVar(value="api_key")
        self.cloud_id_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.api_key_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.verify_ssl_var = tk.BooleanVar(value=True)
        
        self._setup_widgets()
        self.toggle_connection_fields()
        self.toggle_auth_fields()

    def _setup_widgets(self):
        # Connection Type Selection
        ttk.Label(self, text="Connection Type:").grid(row=0, column=0, sticky=tk.W)
        
        ttk.Radiobutton(
            self,
            text="Cloud ID",
            variable=self.connection_type,
            value="cloud_id",
            command=self.toggle_connection_fields
        ).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(
            self,
            text="URL",
            variable=self.connection_type,
            value="url",
            command=self.toggle_connection_fields
        ).grid(row=0, column=2, sticky=tk.W)
        
        # Cloud ID Frame
        self.cloud_frame = ttk.Frame(self)
        self.cloud_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.cloud_frame, text="Cloud ID:").grid(row=0, column=0, sticky=tk.W)
        self.cloud_id_entry = ttk.Entry(self.cloud_frame, textvariable=self.cloud_id_var, width=60)
        self.cloud_id_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        
        # URL Frame
        self.url_frame = ttk.Frame(self)
        self.url_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(self.url_frame, textvariable=self.url_var, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        
        # Authentication Frame
        auth_frame = ttk.LabelFrame(self, text="Authentication", padding="5")
        auth_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Authentication Type Selection
        ttk.Label(auth_frame, text="Auth Type:").grid(row=0, column=0, sticky=tk.W)
        
        ttk.Radiobutton(
            auth_frame,
            text="API Key",
            variable=self.auth_type,
            value="api_key",
            command=self.toggle_auth_fields
        ).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(
            auth_frame,
            text="Basic Auth",
            variable=self.auth_type,
            value="basic",
            command=self.toggle_auth_fields
        ).grid(row=0, column=2, sticky=tk.W)
        
        # API Key Authentication Frame
        self.api_key_frame = ttk.Frame(auth_frame)
        self.api_key_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.api_key_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W)
        self.api_key_entry = ttk.Entry(self.api_key_frame, textvariable=self.api_key_var, width=60, show="*")
        self.api_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        help_label = ttk.Label(
            self.api_key_frame,
            text="Format: encoded_key OR key_id:key_secret",
            font=("TkDefaultFont", 8),
            foreground="gray"
        )
        help_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Basic Authentication Frame
        self.basic_auth_frame = ttk.Frame(auth_frame)
        self.basic_auth_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.basic_auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(self.basic_auth_frame, textvariable=self.username_var, width=60)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        ttk.Label(self.basic_auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(self.basic_auth_frame, textvariable=self.password_var, width=60, show="*")
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # SSL Verification
        ttk.Checkbutton(
            self,
            text="Verify SSL Certificate",
            variable=self.verify_ssl_var
        ).grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))
        
        # Connect Button
        self.connect_btn = ttk.Button(self, text="Connect")
        self.connect_btn.grid(row=5, column=0, columnspan=3, pady=10)

    def toggle_connection_fields(self):
        if self.connection_type.get() == "cloud_id":
            self.cloud_frame.grid()
            self.url_frame.grid_remove()
        else:
            self.cloud_frame.grid_remove()
            self.url_frame.grid()

    def toggle_auth_fields(self):
        if self.auth_type.get() == "api_key":
            self.api_key_frame.grid()
            self.basic_auth_frame.grid_remove()
        else:
            self.api_key_frame.grid_remove()
            self.basic_auth_frame.grid()

    def get_connection_details(self):
        return {
            "connection_type": self.connection_type.get(),
            "cloud_id": self.cloud_id_var.get().strip(),
            "url": self.url_var.get().strip(),
            "auth_type": self.auth_type.get(),
            "api_key": self.api_key_var.get().strip(),
            "username": self.username_var.get().strip(),
            "password": self.password_var.get().strip(),
            "verify_ssl": self.verify_ssl_var.get()
        }