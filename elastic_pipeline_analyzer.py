import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import Listbox, MULTIPLE
import json
from elasticsearch import Elasticsearch
from collections import defaultdict
import webbrowser
import tempfile
import re
import os
import base64

class ElasticInfrastructureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Elasticsearch Pipeline Analyzer")
        self.root.geometry("1200x800")
        
        # Initialize data storage
        self.es_client = None
        self.infrastructure_data = {
            'indices': {},
            'pipelines': {},
            'enrich_policies': {},
            'relationships': defaultdict(list)
        }
        
        # Store processor details for hover
        self.processor_details = {}
        
        main_container = ttk.Frame(root, padding="10")
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.setup_credentials_frame(main_container)
        self.setup_analysis_frame(main_container)
        self.setup_results_frame(main_container)
        
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_container.columnconfigure(1, weight=1)
        main_container.rowconfigure(2, weight=1)

    def setup_credentials_frame(self, parent):
        creds_frame = ttk.LabelFrame(parent, text="Elasticsearch Connection", padding="10")
        creds_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Connection Type Selection
        ttk.Label(creds_frame, text="Connection Type:").grid(row=0, column=0, sticky=tk.W)
        self.connection_type = tk.StringVar(value="cloud_id")
        
        ttk.Radiobutton(
            creds_frame,
            text="Cloud ID",
            variable=self.connection_type,
            value="cloud_id",
            command=self.toggle_connection_fields
        ).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(
            creds_frame,
            text="URL",
            variable=self.connection_type,
            value="url",
            command=self.toggle_connection_fields
        ).grid(row=0, column=2, sticky=tk.W)
        
        # Cloud ID Frame
        self.cloud_frame = ttk.Frame(creds_frame)
        self.cloud_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.cloud_frame, text="Cloud ID:").grid(row=0, column=0, sticky=tk.W)
        self.cloud_id_var = tk.StringVar()
        self.cloud_id_entry = ttk.Entry(self.cloud_frame, textvariable=self.cloud_id_var, width=60)
        self.cloud_id_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        
        # URL Frame
        self.url_frame = ttk.Frame(creds_frame)
        self.url_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(self.url_frame, textvariable=self.url_var, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        
        # Authentication Frame
        auth_frame = ttk.LabelFrame(creds_frame, text="Authentication", padding="5")
        auth_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Authentication Type Selection
        ttk.Label(auth_frame, text="Auth Type:").grid(row=0, column=0, sticky=tk.W)
        self.auth_type = tk.StringVar(value="api_key")
        
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
        self.api_key_var = tk.StringVar()
        self.api_key_entry = ttk.Entry(self.api_key_frame, textvariable=self.api_key_var, width=60)
        self.api_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        ttk.Label(self.api_key_frame, text="API Secret:").grid(row=1, column=0, sticky=tk.W)
        self.api_secret_var = tk.StringVar()
        self.api_secret_entry = ttk.Entry(self.api_key_frame, textvariable=self.api_secret_var, width=60, show="*")
        self.api_secret_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # Basic Authentication Frame
        self.basic_auth_frame = ttk.Frame(auth_frame)
        self.basic_auth_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        
        ttk.Label(self.basic_auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(self.basic_auth_frame, textvariable=self.username_var, width=60)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        ttk.Label(self.basic_auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.basic_auth_frame, textvariable=self.password_var, width=60, show="*")
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # SSL Verification
        self.verify_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            creds_frame,
            text="Verify SSL Certificate",
            variable=self.verify_ssl_var
        ).grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))
        
        # Connect Button
        self.connect_btn = ttk.Button(creds_frame, text="Connect", command=self.connect_to_elasticsearch)
        self.connect_btn.grid(row=5, column=0, columnspan=3, pady=10)
        
        # Initial visibility setup
        self.toggle_connection_fields()
        self.toggle_auth_fields()

    def toggle_connection_fields(self):
        """Toggle visibility of connection fields based on connection type."""
        if self.connection_type.get() == "cloud_id":
            self.cloud_frame.grid()
            self.url_frame.grid_remove()
        else:
            self.cloud_frame.grid_remove()
            self.url_frame.grid()

    def toggle_auth_fields(self):
        """Toggle visibility of authentication fields based on auth type."""
        if self.auth_type.get() == "api_key":
            self.api_key_frame.grid()
            self.basic_auth_frame.grid_remove()
        else:
            self.api_key_frame.grid_remove()
            self.basic_auth_frame.grid()

    def setup_analysis_frame(self, parent):
        analysis_frame = ttk.LabelFrame(parent, text="Analysis Options", padding="10")
        analysis_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(analysis_frame, text="Start Analysis From:").grid(row=0, column=0, sticky=tk.W)
        self.analysis_type = tk.StringVar(value="index")
        
        ttk.Radiobutton(
            analysis_frame, 
            text="Index", 
            variable=self.analysis_type, 
            value="index",
            command=self.update_selection_list
        ).grid(row=0, column=1)
        
        ttk.Radiobutton(
            analysis_frame, 
            text="Pipeline", 
            variable=self.analysis_type, 
            value="pipeline",
            command=self.update_selection_list
        ).grid(row=0, column=2)
        
        ttk.Radiobutton(
            analysis_frame, 
            text="Enrichment Policy", 
            variable=self.analysis_type, 
            value="enrich",
            command=self.update_selection_list
        ).grid(row=0, column=3)
        
        search_frame = ttk.Frame(analysis_frame)
        search_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_selection_list)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=50)
        search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        list_frame = ttk.Frame(analysis_frame)
        list_frame.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E))
        
        self.selection_list = Listbox(list_frame, selectmode=MULTIPLE, height=6)
        self.selection_list.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.selection_list.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.selection_list.configure(yscrollcommand=scrollbar.set)
        
        list_frame.columnconfigure(0, weight=1)
        
        self.analyze_btn = ttk.Button(
            analysis_frame, 
            text="Analyze", 
            command=self.analyze_infrastructure,
            state=tk.DISABLED
        )
        self.analyze_btn.grid(row=3, column=0, columnspan=4, pady=10)

    def setup_results_frame(self, parent):
        results_frame = ttk.LabelFrame(parent, text="Results", padding="10")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        button_frame = ttk.Frame(results_frame)
        button_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.view_btn = ttk.Button(
            button_frame, 
            text="View Diagram", 
            command=self.view_diagram,
            state=tk.DISABLED
        )
        self.view_btn.grid(row=0, column=0, padx=5)
        
        text_frame = ttk.Frame(results_frame)
        text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.results_text = scrolledtext.ScrolledText(
            text_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20
        )
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)

    def get_processor_details(self, processor):
        """Extract readable configuration details from a processor."""
        processor_type = next(iter(processor.keys()))
        config = processor[processor_type]
        
        # Format the configuration details
        details = []
        if isinstance(config, dict):
            for key, value in config.items():
                if key != 'if' and key != 'ignore_failure':  # Skip common conditionals
                    details.append(f"{key}: {value}")
        
        return details

    def connect_to_elasticsearch(self):
        """Establish connection to Elasticsearch using selected connection method."""
        try:
            # Prepare connection kwargs
            es_kwargs = {
                'verify_certs': self.verify_ssl_var.get()
            }
            
            # Add connection details based on connection type
            if self.connection_type.get() == "cloud_id":
                cloud_id = self.cloud_id_var.get().strip()
                if not cloud_id:
                    raise ValueError("Cloud ID is required")
                es_kwargs['cloud_id'] = cloud_id
            else:
                url = self.url_var.get().strip()
                if not url:
                    raise ValueError("URL is required")
                es_kwargs['hosts'] = [url]
            
            # Add authentication details based on auth type
            if self.auth_type.get() == "api_key":
                api_key = self.api_key_var.get().strip()
                api_secret = self.api_secret_var.get().strip()
                if not all([api_key, api_secret]):
                    raise ValueError("API Key and Secret are required")
                es_kwargs['api_key'] = (api_key, api_secret)
            else:
                username = self.username_var.get().strip()
                password = self.password_var.get().strip()
                if not all([username, password]):
                    raise ValueError("Username and Password are required")
                es_kwargs['basic_auth'] = (username, password)
            
            # Create Elasticsearch client
            self.es_client = Elasticsearch(**es_kwargs)
            
            # Test connection
            if not self.es_client.ping():
                raise Exception("Failed to connect to Elasticsearch")
            
            # Fetch initial data
            self.fetch_infrastructure_data()
            
            self.analyze_btn.config(state=tk.NORMAL)
            self.update_selection_list()
            
            messagebox.showinfo("Success", "Connected to Elasticsearch successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            self.es_client = None

    def fetch_infrastructure_data(self):
        """Fetch all required data from Elasticsearch."""
        try:
            # Fetch indices with their settings
            indices_response = self.es_client.indices.get_settings(flat_settings=True)
            for index_name, settings in indices_response.items():
                index_settings = settings.get('settings', {})
                self.infrastructure_data['indices'][index_name] = {
                    'default_pipeline': index_settings.get('index.default_pipeline'),
                    'final_pipeline': index_settings.get('index.final_pipeline'),
                    'pipeline_chains': []  # Will store complete pipeline chains
                }

            # Fetch all pipelines and analyze their processors
            pipelines = self.es_client.ingest.get_pipeline()
            for name, info in pipelines.items():
                self.infrastructure_data['pipelines'][name] = {
                    'processors': info['processors'],
                    'description': info.get('description', ''),
                    'called_by': set(),  # Track which pipelines call this one
                    'calls_pipelines': set(),  # Track which pipelines this one calls
                    'uses_enrich': set()  # Track which enrich policies are used
                }

            # Store processor details for hover
            for pipeline_name, pipeline_info in self.infrastructure_data['pipelines'].items():
                self.processor_details[pipeline_name] = [
                    (next(iter(p.keys())), self.get_processor_details(p))
                    for p in pipeline_info['processors']
                ]

            # Fetch enrich policies
            try:
                enrich_response = self.es_client.enrich.get_policy()
                policies = enrich_response.body.get('policies', [])
            except Exception as e:
                print(f"Warning: Could not fetch enrich policies: {str(e)}")
                policies = []

            for policy in policies:
                name = policy['config']['match']['name']
                self.infrastructure_data['enrich_policies'][name] = {
                    'source_indices': policy['config']['match']['indices'],
                    'match_field': policy['config']['match']['match_field'],
                    'used_by_pipelines': set()  # Track which pipelines use this policy
                }

            self.build_relationships()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch data: {str(e)}")
            raise

    def build_relationships(self):
        """Build comprehensive relationship graph between components."""
        relationships = defaultdict(list)
        
        # First pass: Analyze pipeline processors and build pipeline-to-pipeline relationships
        for pipeline_name, pipeline_info in self.infrastructure_data['pipelines'].items():
            for processor in pipeline_info['processors']:
                if 'pipeline' in processor:
                    target_pipeline = processor['pipeline']['name']
                    pipeline_info['calls_pipelines'].add(target_pipeline)
                    # Add the reverse relationship
                    if target_pipeline in self.infrastructure_data['pipelines']:
                        self.infrastructure_data['pipelines'][target_pipeline]['called_by'].add(pipeline_name)
                    relationships[pipeline_name].append(('pipeline', target_pipeline, 'calls'))
                
                elif 'enrich' in processor:
                    policy_name = processor['enrich']['policy_name']
                    pipeline_info['uses_enrich'].add(policy_name)
                    if policy_name in self.infrastructure_data['enrich_policies']:
                        self.infrastructure_data['enrich_policies'][policy_name]['used_by_pipelines'].add(pipeline_name)
                    relationships[pipeline_name].append(('enrich', policy_name, 'enriches with'))
        
        # Second pass: Build complete pipeline chains for each index
        for index_name, index_info in self.infrastructure_data['indices'].items():
            # Track all pipelines related to this index
            index_pipelines = set()
            
            # Process default pipeline
            if index_info['default_pipeline']:
                default_chain = self.get_pipeline_chain(index_info['default_pipeline'])
                index_info['pipeline_chains'].extend(default_chain)
                index_pipelines.update(default_chain)
                relationships[index_name].append(('pipeline', index_info['default_pipeline'], 'default'))
            
            # Process final pipeline
            if index_info['final_pipeline']:
                final_chain = self.get_pipeline_chain(index_info['final_pipeline'])
                index_info['pipeline_chains'].extend(final_chain)
                index_pipelines.update(final_chain)
                relationships[index_name].append(('pipeline', index_info['final_pipeline'], 'final'))
            
            # Add relationships for all pipelines in the chain
            for pipeline_name in index_pipelines:
                if pipeline_name in self.infrastructure_data['pipelines']:
                    pipeline_info = self.infrastructure_data['pipelines'][pipeline_name]
                    
                    # Add enrichment relationships
                    for policy_name in pipeline_info['uses_enrich']:
                        relationships[pipeline_name].append(('enrich', policy_name, 'enriches with'))
                        
                        # Add source indices for enrich policies
                        if policy_name in self.infrastructure_data['enrich_policies']:
                            policy_info = self.infrastructure_data['enrich_policies'][policy_name]
                            for source_index in policy_info['source_indices']:
                                relationships[policy_name].append(('index', source_index, 'source'))
        
        self.infrastructure_data['relationships'] = relationships

    def get_pipeline_chain(self, start_pipeline, visited=None):
        """Recursively get the chain of pipelines starting from a given pipeline."""
        if visited is None:
            visited = set()
        
        if start_pipeline in visited or start_pipeline not in self.infrastructure_data['pipelines']:
            return []
        
        visited.add(start_pipeline)
        chain = [start_pipeline]
        
        # Get all pipelines called by this pipeline
        pipeline_info = self.infrastructure_data['pipelines'][start_pipeline]
        for processor in pipeline_info.get('processors', []):
            if 'pipeline' in processor:
                called_pipeline = processor['pipeline']['name']
                chain.extend(self.get_pipeline_chain(called_pipeline, visited))
        
        return chain

    def update_selection_list(self, *args):
        """Update the selection list based on current analysis type."""
        self.selection_list.delete(0, tk.END)
        
        analysis_type = self.analysis_type.get()
        items = []
        
        if analysis_type == "index":
            items = sorted(self.infrastructure_data['indices'].keys())
        elif analysis_type == "pipeline":
            items = sorted(self.infrastructure_data['pipelines'].keys())
        elif analysis_type == "enrich":
            items = sorted(self.infrastructure_data['enrich_policies'].keys())
        
        for item in items:
            self.selection_list.insert(tk.END, item)

    def filter_selection_list(self, *args):
        """Filter the selection list based on search text."""
        search_text = self.search_var.get().lower()
        self.update_selection_list()
        
        if search_text:
            items = [item for item in self.selection_list.get(0, tk.END)
                    if search_text in item.lower()]
            self.selection_list.delete(0, tk.END)
            for item in items:
                self.selection_list.insert(tk.END, item)

    def analyze_infrastructure(self):
        """Analyze infrastructure based on selected items."""
        selected_indices = self.selection_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select at least one item")
            return
            
        selected_items = [self.selection_list.get(i) for i in selected_indices]
        analysis_type = self.analysis_type.get()
        
        # Generate diagram based on selection
        diagram = self.generate_mermaid_diagram(selected_items, analysis_type)
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, diagram)
        
        self.view_btn.config(state=tk.NORMAL)

    def generate_mermaid_diagram(self, selected_items, analysis_type):
        """Generate enhanced Mermaid diagram code with hover details."""
        mermaid_code = ["graph TD"]
        visited = set()
        node_styles = set()
        
        def add_node(node_id, label, node_type, additional_info=None, processors=None):
            """Helper function to add nodes with consistent formatting."""
            node_label = [label]
            
            if additional_info:
                node_label.append(additional_info)
            
            if processors:
                # Format processors as a numbered list with hover details
                processor_list = []
                for i, (p_type, p_details) in enumerate(processors):
                    hover_text = "<br/>".join(p_details) if p_details else "No additional configuration"
                    processor_list.append(f"{i+1}. {p_type}")
                
                node_label.append("Processors:<br/>" + "<br/>".join(processor_list))
            
            final_label = "<br/>".join(node_label)
            
            if node_type == 'index':
                mermaid_code.append(f"    {node_id}[(\"{final_label}\")]")
            elif node_type == 'pipeline':
                mermaid_code.append(f"    {node_id}[\"{final_label}\"]")
            elif node_type == 'enrich':
                mermaid_code.append(f"    {node_id}(\"{final_label}\")")
            elif node_type == 'processors':
                mermaid_code.append(f"    {node_id}{{\"{final_label}\"}}")
            
            node_styles.add((node_id, node_type))

        def add_processor_node(pipeline_name, pipeline_info):
            """Add a single processor node containing all processors for a pipeline."""
            pipeline_node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', pipeline_name)}_pipeline"
            processors_node_id = f"{pipeline_node_id}_processors"
            
            # Get processor details
            processors = self.processor_details.get(pipeline_name, [])
            
            if processors:
                # Add the processor node
                add_node(
                    processors_node_id,
                    "Processor Chain",
                    'processors',
                    None,
                    processors
                )
                
                # Connect pipeline to its processors
                mermaid_code.append(f"    {pipeline_node_id} --> {processors_node_id}")

        def add_relationships(item, component_type):
            if (item, component_type) in visited:
                return
            visited.add((item, component_type))
            
            node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', item)}_{component_type}"
            
            if component_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                called_by = len(pipeline_info.get('called_by', set()))
                called_pipelines = len(pipeline_info.get('calls_pipelines', set()))
                
                metadata = [
                    f"{processor_count} processors",
                    f"Called by: {called_by}",
                    f"Calls: {called_pipelines}"
                ]
                
                add_node(node_id, item, 'pipeline', "<br/>".join(metadata))
                add_processor_node(item, pipeline_info)
                
                for target in pipeline_info.get('calls_pipelines', set()):
                    target_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', target)}_pipeline"
                    mermaid_code.append(f"    {node_id} -->|calls| {target_id}")
                    add_relationships(target, 'pipeline')
                
                for policy in pipeline_info.get('uses_enrich', set()):
                    policy_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', policy)}_enrich"
                    mermaid_code.append(f"    {node_id} -->|enriches with| {policy_id}")
                    add_relationships(policy, 'enrich')
            
            elif component_type == 'index':
                index_info = self.infrastructure_data['indices'].get(item, {})
                pipeline_chains = len(index_info.get('pipeline_chains', []))
                metadata = [f"Pipeline chain length: {pipeline_chains}"]
                
                if index_info.get('default_pipeline'):
                    metadata.append(f"Default: {index_info['default_pipeline']}")
                if index_info.get('final_pipeline'):
                    metadata.append(f"Final: {index_info['final_pipeline']}")
                
                add_node(node_id, item, 'index', "<br/>".join(metadata))
                
                if index_info.get('default_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', index_info['default_pipeline'])}_pipeline"
                    mermaid_code.append(f"    {node_id} -->|default| {pipeline_id}")
                    add_relationships(index_info['default_pipeline'], 'pipeline')
                
                if index_info.get('final_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', index_info['final_pipeline'])}_pipeline"
                    mermaid_code.append(f"    {node_id} -->|final| {pipeline_id}")
                    add_relationships(index_info['final_pipeline'], 'pipeline')
            
            elif component_type == 'enrich':
                policy_info = self.infrastructure_data['enrich_policies'].get(item, {})
                source_indices = len(policy_info.get('source_indices', []))
                used_by = len(policy_info.get('used_by_pipelines', set()))
                
                metadata = [
                    f"Source indices: {source_indices}",
                    f"Used by: {used_by} pipelines"
                ]
                
                add_node(node_id, item, 'enrich', "<br/>".join(metadata))
                
                for source_index in policy_info.get('source_indices', []):
                    index_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', source_index)}_index"
                    mermaid_code.append(f"    {node_id} -->|source| {index_id}")
                    add_relationships(source_index, 'index')
        
        for item in selected_items:
            add_relationships(item, analysis_type)
        
        mermaid_code.extend([
            "    classDef index fill:#bfe,stroke:#333,stroke-width:2px;",
            "    classDef pipeline fill:#ebf,stroke:#333,stroke-width:2px;",
            "    classDef enrich fill:#fbe,stroke:#333,stroke-width:2px;",
            "    classDef processors fill:#fef,stroke:#333,stroke-width:1px;",
        ])
        
        for node_id, node_type in node_styles:
            mermaid_code.append(f"    class {node_id} {node_type};")
        
        return "\n".join(mermaid_code)

    def view_diagram(self):
        """View the current diagram in a browser window with enhanced features."""
        if not self.results_text.get(1.0, tk.END).strip():
            messagebox.showerror("Error", "No diagram to display")
            return
        
        diagram_code = self.results_text.get(1.0, tk.END).strip()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Elasticsearch Pipeline Relationships</title>
            <script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.0/dist/mermaid.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js"></script>
            <script>
                mermaid.initialize({{ 
                    startOnLoad: true, 
                    theme: 'default',
                    maxTextSize: 100000,
                    securityLevel: 'loose',
                    flowchart: {{
                        nodeSpacing: 50,
                        rankSpacing: 50,
                        curve: 'basis',
                        htmlLabels: true
                    }}
                }});

                // Zoom functionality
                let currentZoom = 1;
                function zoom(factor) {{
                    currentZoom *= factor;
                    document.querySelector('.mermaid').style.transform = `scale(${{currentZoom}})`;
                }}

                // Export functionality
                async function exportAsPNG() {{
                    try {{
                        const svgElement = document.querySelector('.mermaid svg');
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');

                        // Set size to 2x for better quality
                        const scale = 1;
                        canvas.width = svgElement.clientWidth * scale;
                        canvas.height = svgElement.clientHeight * scale;

                        // Create image from SVG
                        const svgString = new XMLSerializer().serializeToString(svgElement);
                        const img = new Image();
                        img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgString)));

                        await new Promise((resolve, reject) => {{
                            img.onload = resolve;
                            img.onerror = reject;
                        }});

                        // Draw with white background
                        ctx.fillStyle = 'white';
                        ctx.fillRect(0, 0, canvas.width, canvas.height);
                        ctx.scale(scale, scale);
                        ctx.drawImage(img, 0, 0);

                        // Convert to blob and save
                        canvas.toBlob((blob) => {{
                            saveAs(blob, 'pipeline_diagram.png');
                        }}, 'image/png');
                    }} catch (error) {{
                        alert('Failed to export PNG. Please try using SVG export instead.');
                    }}
                }}

                function exportAsSVG() {{
                    const svgElement = document.querySelector('.mermaid svg');
                    const svgData = new XMLSerializer().serializeToString(svgElement);
                    const blob = new Blob([svgData], {{type: 'image/svg+xml'}});
                    saveAs(blob, 'pipeline_diagram.svg');
                }}
            </script>
            <style>
                body {{
                    margin: 20px;
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .controls {{
                    margin-bottom: 20px;
                }}
                .mermaid {{
                    background: white;
                    padding: 20px;
                    border-radius: 4px;
                    overflow: auto;
                    transform-origin: center;
                    transition: transform 0.2s;
                }}
                .legend {{
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                }}
                .legend-item {{
                    display: inline-block;
                    margin-right: 20px;
                    margin-bottom: 10px;
                }}
                .legend-color {{
                    display: inline-block;
                    width: 20px;
                    height: 20px;
                    margin-right: 5px;
                    vertical-align: middle;
                    border: 1px solid #333;
                }}
                .index-color {{ background-color: #bfe; }}
                .pipeline-color {{ background-color: #ebf; }}
                .enrich-color {{ background-color: #fbe; }}
                .processor-color {{ background-color: #fef; }}

                .zoom-controls {{
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    background: white;
                    padding: 10px;
                    border-radius: 4px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    z-index: 1000;
                }}

                .export-controls {{
                    position: fixed;
                    bottom: 20px;
                    left: 20px;
                    background: white;
                    padding: 10px;
                    border-radius: 4px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    z-index: 1000;
                }}

                .zoom-btn, .export-btn {{
                    margin: 0 5px;
                    padding: 5px 10px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: #f8f8f8;
                    cursor: pointer;
                }}

                .zoom-btn:hover, .export-btn:hover {{
                    background: #eee;
                }}

                #processor-tooltip {{
                    display: none;
                    position: absolute;
                    background: white;
                    border: 1px solid #ddd;
                    padding: 10px;
                    border-radius: 4px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    z-index: 1000;
                    max-width: 300px;
                }}

                .relationship-types {{
                    margin-top: 15px;
                    font-size: 0.9em;
                }}
                .relationship-type {{
                    display: inline-block;
                    margin-right: 20px;
                    padding: 5px 10px;
                    background-color: #f8f8f8;
                    border-radius: 4px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="controls">
                    <h2>Elasticsearch Pipeline Relationships</h2>
                </div>
                <div class="mermaid">
                {diagram_code}
                </div>
                <div id="processor-tooltip"></div>
                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="zoom(1.2)">Zoom In</button>
                    <button class="zoom-btn" onclick="zoom(0.8)">Zoom Out</button>
                    <button class="zoom-btn" onclick="zoom(1/currentZoom)">Reset</button>
                </div>
                <div class="export-controls">
                    <button class="export-btn" onclick="exportAsPNG()">Export as PNG</button>
                    <button class="export-btn" onclick="exportAsSVG()">Export as SVG</button>
                </div>
                <div class="legend">
                    <h3>Legend</h3>
                    <div class="legend-item">
                        <span class="legend-color index-color"></span>
                        Index (Database shape)
                    </div>
                    <div class="legend-item">
                        <span class="legend-color pipeline-color"></span>
                        Pipeline (Rectangle)
                    </div>
                    <div class="legend-item">
                        <span class="legend-color enrich-color"></span>
                        Enrichment Policy (Rounded Rectangle)
                    </div>
                    <div class="legend-item">
                        <span class="legend-color processor-color"></span>
                        Processors (Diamond)
                    </div>
                    <div class="relationship-types">
                        <h4>Relationship Types:</h4>
                        <span class="relationship-type">default → Default Pipeline</span>
                        <span class="relationship-type">final → Final Pipeline</span>
                        <span class="relationship-type">calls → Pipeline Reference</span>
                        <span class="relationship-type">enriches with → Enrichment Process</span>
                        <span class="relationship-type">source → Source Index</span>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create temporary HTML file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as f:
            f.write(html_content)
            temp_path = f.name
        
        # Open in browser
        webbrowser.open(f'file://{temp_path}')
        
        # Schedule cleanup of temp file
        self.root.after(1000, lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)

def main():
    root = tk.Tk()
    app = ElasticInfrastructureGUI(root)
    
    # Center the window
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width/2) - (1200/2)
    y = (screen_height/2) - (800/2)
    root.geometry(f'1200x800+{int(x)}+{int(y)}')
    
    # Make window resizable
    root.resizable(True, True)
    
    # Configure grid weights
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
