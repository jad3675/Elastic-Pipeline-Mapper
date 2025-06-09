import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import Listbox, MULTIPLE
import json
from elasticsearch import Elasticsearch
from collections import defaultdict, Counter
import webbrowser
import tempfile
import re
import os
import base64

class ElasticInfrastructureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Elasticsearch Pipeline Analyzer - Multi-Level Visualization")
        self.root.geometry("1200x900")
        
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
        
        # Processor categorization mapping
        self.processor_phases = {
            'input_parsing': {
                'name': '📥 Input & Parsing',
                'processors': ['grok', 'json', 'csv', 'dissect', 'kv', 'xml', 'split', 'gsub'],
                'color': '#e1f5fe'
            },
            'transformation': {
                'name': '🔄 Data Transformation', 
                'processors': ['set', 'remove', 'rename', 'convert', 'mutate', 'trim', 'lowercase', 'uppercase', 'append'],
                'color': '#f3e5f5'
            },
            'enrichment': {
                'name': '📈 Enrichment',
                'processors': ['enrich', 'geoip', 'user_agent', 'dns', 'community_id'],
                'color': '#e8f5e8'
            },
            'processing': {
                'name': '⚙️ Processing & Validation',
                'processors': ['script', 'conditional', 'foreach', 'if', 'fail', 'drop'],
                'color': '#fff3e0'
            },
            'formatting': {
                'name': '📋 Formatting & Output',
                'processors': ['date', 'fingerprint', 'bytes', 'urldecode', 'html_strip', 'attachment'],
                'color': '#fce4ec'
            },
            'orchestration': {
                'name': '🔗 Pipeline Orchestration',
                'processors': ['pipeline'],
                'color': '#e0f2f1'
            }
        }
        
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
        self.api_key_entry = ttk.Entry(self.api_key_frame, textvariable=self.api_key_var, width=60, show="*")
        self.api_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        
        # Add helpful label for API key format
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
        
        # Start Analysis From section
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
        
        # Visualization Level Selection - NEW SECTION
        ttk.Separator(analysis_frame, orient='horizontal').grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(analysis_frame, text="Visualization Level:").grid(row=2, column=0, sticky=tk.W)
        self.visualization_level = tk.StringVar(value="overview")
        
        level_frame = ttk.Frame(analysis_frame)
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
        level_desc_frame = ttk.Frame(analysis_frame)
        level_desc_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        level_descriptions = ttk.Label(
            level_desc_frame,
            text="📊 Overview: High-level pipeline relationships | 🔧 Pipeline Detail: Logical processing phases | 🔬 Processor Detail: Detailed processor groups",
            font=("TkDefaultFont", 8),
            foreground="gray"
        )
        level_descriptions.grid(row=0, column=0, sticky=tk.W)
        
        # Search and selection section
        search_frame = ttk.Frame(analysis_frame)
        search_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_selection_list)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=50)
        search_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        list_frame = ttk.Frame(analysis_frame)
        list_frame.grid(row=5, column=0, columnspan=4, sticky=(tk.W, tk.E))
        
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
        self.analyze_btn.grid(row=6, column=0, columnspan=4, pady=10)

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

    def categorize_processor(self, processor_type):
        """Categorize a processor type into its logical phase."""
        for phase_id, phase_info in self.processor_phases.items():
            if processor_type in phase_info['processors']:
                return phase_id
        return 'processing'  # Default category for unknown processors

    def get_pipeline_phases(self, pipeline_name):
        """Analyze a pipeline's processors and group them by logical phases."""
        if pipeline_name not in self.infrastructure_data['pipelines']:
            return {}
        
        pipeline_info = self.infrastructure_data['pipelines'][pipeline_name]
        phases = defaultdict(list)
        
        for processor in pipeline_info['processors']:
            processor_type = next(iter(processor.keys()))
            phase = self.categorize_processor(processor_type)
            phases[phase].append({
                'type': processor_type,
                'config': processor[processor_type],
                'details': self.get_processor_details(processor)
            })
        
        return dict(phases)

    def get_phase_statistics(self, phases):
        """Generate statistics for pipeline phases."""
        stats = {}
        total_processors = sum(len(processors) for processors in phases.values())
        
        for phase_id, processors in phases.items():
            processor_types = Counter(p['type'] for p in processors)
            most_common = processor_types.most_common(1)
            top_processor = most_common[0] if most_common else ('none', 0)
            
            stats[phase_id] = {
                'count': len(processors),
                'percentage': (len(processors) / total_processors * 100) if total_processors > 0 else 0,
                'top_processor': top_processor[0],
                'processor_types': dict(processor_types)
            }
        
        return stats, total_processors

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
                api_key_str = self.api_key_var.get().strip()
                if not api_key_str:
                    raise ValueError("API Key is required")
                
                # Handle both formats: key_id:key_secret or encoded_key
                if ':' in api_key_str:
                    api_key_id, api_key_secret = api_key_str.split(':', 1)
                    es_kwargs['api_key'] = (api_key_id, api_key_secret)
                else:
                    # Assumed to be base64 encoded key
                    es_kwargs['api_key'] = api_key_str
            else:
                username = self.username_var.get().strip()
                password = self.password_var.get().strip()
                if not username:
                    raise ValueError("Username is required")
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

    def generate_interactive_data(self, selected_items, analysis_type):
        """Generate data structure for interactive visualization."""
        nodes = []
        edges = []
        visited = set()
        
        # Get the current visualization level to determine what to show
        visualization_level = self.visualization_level.get()
        
        def add_node_data(item_id, item_name, node_type, metadata=None, detailed_info=None):
            """Add node data with hover and click information."""
            node_data = {
                'id': item_id,
                'label': item_name,
                'type': node_type,
                'metadata': metadata or {},
                'detailed_info': detailed_info or {}
            }
            
            # Set node styling based on type
            if node_type == 'index':
                node_data.update({
                    'color': {'background': '#e1f5fe', 'border': '#0277bd'},
                    'shape': 'database',
                    'font': {'color': '#0277bd'}
                })
            elif node_type == 'pipeline':
                node_data.update({
                    'color': {'background': '#f3e5f5', 'border': '#7b1fa2'},
                    'shape': 'box',
                    'font': {'color': '#7b1fa2'}
                })
            elif node_type == 'enrich':
                node_data.update({
                    'color': {'background': '#e8f5e8', 'border': '#388e3c'},
                    'shape': 'ellipse',
                    'font': {'color': '#388e3c'}
                })
            elif node_type == 'phase':
                node_data.update({
                    'color': {'background': '#fff3e0', 'border': '#f57c00'},
                    'shape': 'diamond',
                    'font': {'color': '#f57c00'}
                })
            elif node_type == 'processor_group':
                node_data.update({
                    'color': {'background': '#fce4ec', 'border': '#c2185b'},
                    'shape': 'dot',
                    'font': {'color': '#c2185b'}
                })
            
            nodes.append(node_data)
        
        def add_edge_data(from_id, to_id, label, edge_type='default'):
            """Add edge data with styling."""
            edge_data = {
                'from': from_id,
                'to': to_id,
                'label': label,
                'type': edge_type
            }
            
            # Set edge styling based on type
            if edge_type == 'calls':
                edge_data.update({
                    'color': {'color': '#ff9800'},
                    'arrows': {'to': {'enabled': True}},
                    'dashes': False
                })
            elif edge_type == 'enriches':
                edge_data.update({
                    'color': {'color': '#4caf50'},
                    'arrows': {'to': {'enabled': True}},
                    'dashes': [5, 5]
                })
            else:
                edge_data.update({
                    'color': {'color': '#2196f3'},
                    'arrows': {'to': {'enabled': True}},
                    'dashes': False
                })
            
            edges.append(edge_data)
        
        def add_pipeline_phases_interactive(pipeline_name, pipeline_node_id):
            """Add phase nodes for pipeline detail level in interactive visualization."""
            if visualization_level != 'pipeline_detail':
                return pipeline_node_id  # Return original node if not pipeline detail level
                
            phases = self.get_pipeline_phases(pipeline_name)
            
            # If no phases detected, create a generic processing phase for any processors
            if not phases:
                pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                actual_processors = [next(iter(p.keys())) for p in pipeline_info.get('processors', [])]
                if actual_processors:
                    phases = {
                        'processing': [{
                            'type': proc_type,
                            'config': {},
                            'details': []
                        } for proc_type in actual_processors]
                    }
            
            if not phases:
                return pipeline_node_id
                
            stats, total_processors = self.get_phase_statistics(phases)
            
            prev_phase_id = pipeline_node_id
            last_phase_id = pipeline_node_id
            
            # Sort phases by logical order
            phase_order = ['input_parsing', 'transformation', 'enrichment', 'processing', 'formatting', 'orchestration']
            ordered_phases = [(p, phases[p]) for p in phase_order if p in phases]
            
            for phase_id, processors in ordered_phases:
                phase_info = self.processor_phases[phase_id]
                phase_node_id = f"{pipeline_node_id}_{phase_id}"
                
                # Create phase summary
                stat = stats.get(phase_id, {'count': 0, 'percentage': 0, 'top_processor': 'none'})
                phase_label = f"{phase_info['name']}\n({stat['count']} processors, {stat['percentage']:.1f}%)\nTop: {stat['top_processor']}"
                
                # Create metadata for the phase
                phase_metadata = {
                    'processor_count': stat['count'],
                    'percentage': stat['percentage'],
                    'top_processor': stat['top_processor'],
                    'phase_name': phase_info['name']
                }
                
                # Create detailed info for the phase
                phase_detailed_info = {
                    'processors': processors,
                    'processor_types': stat.get('processor_types', {}),
                    'phase_description': f"This phase handles {phase_info['name'].lower()} operations"
                }
                
                add_node_data(phase_node_id, phase_label, 'phase', phase_metadata, phase_detailed_info)
                
                # Connect pipeline to first phase or phase to phase
                if prev_phase_id == pipeline_node_id:
                    add_edge_data(pipeline_node_id, phase_node_id, 'processes')
                else:
                    add_edge_data(prev_phase_id, phase_node_id, 'then')
                
                prev_phase_id = phase_node_id
                last_phase_id = phase_node_id
                
                # Add connections to enrichment policies if this is an enrichment phase
                if phase_id == 'enrichment':
                    pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                    for policy in pipeline_info.get('uses_enrich', set()):
                        policy_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', policy)}_enrich"
                        add_edge_data(phase_node_id, policy_id, 'uses')
                        # Note: We'll process the enrich policy separately
            
            return last_phase_id
        
        def add_processor_groups_interactive(pipeline_name, pipeline_node_id):
            """Add processor group nodes for processor detail level in interactive visualization."""
            if visualization_level != 'processor_detail':
                return pipeline_node_id  # Return original node if not processor detail level
                
            phases = self.get_pipeline_phases(pipeline_name)
            
            if not phases:
                return pipeline_node_id
            
            phase_order = ['input_parsing', 'transformation', 'enrichment', 'processing', 'formatting', 'orchestration']
            ordered_phases = [(p, phases[p]) for p in phase_order if p in phases]
            
            prev_element_id = pipeline_node_id
            
            for phase_id, processors in ordered_phases:
                phase_info = self.processor_phases[phase_id]
                phase_node_id = f"{pipeline_node_id}_{phase_id}"
                
                # Group processors by type within this phase
                processor_groups = defaultdict(list)
                for processor in processors:
                    processor_groups[processor['type']].append(processor)
                
                if len(processor_groups) == 1:
                    # Single processor type - create one group node
                    proc_type = list(processor_groups.keys())[0]
                    group_node_id = f"{phase_node_id}_{proc_type}"
                    
                    # Sample configuration from first processor
                    sample_config = []
                    if processor_groups[proc_type]:
                        sample_proc = processor_groups[proc_type][0]
                        if isinstance(sample_proc['config'], dict):
                            config_items = list(sample_proc['config'].items())[:2]
                            for key, value in config_items:
                                if key not in ['if', 'ignore_failure']:
                                    sample_config.append(f"{key}: {str(value)[:15]}...")
                    
                    group_label = f"{phase_info['name']}\n{proc_type} ({len(processor_groups[proc_type])}x)"
                    if sample_config:
                        group_label += f"\nConfig: {', '.join(sample_config[:1])}"
                    
                    group_metadata = {
                        'processor_type': proc_type,
                        'count': len(processor_groups[proc_type]),
                        'phase_name': phase_info['name'],
                        'sample_config': sample_config
                    }
                    
                    group_detailed_info = {
                        'processors': processor_groups[proc_type],
                        'phase_id': phase_id
                    }
                    
                    add_node_data(group_node_id, group_label, 'processor_group', group_metadata, group_detailed_info)
                    add_edge_data(prev_element_id, group_node_id, 'contains')
                    prev_element_id = group_node_id
                    
                else:
                    # Multiple processor types - create phase node and individual groups
                    phase_label = f"{phase_info['name']}\n({len(processors)} processors)"
                    
                    phase_metadata = {
                        'processor_count': len(processors),
                        'phase_name': phase_info['name'],
                        'processor_types': list(processor_groups.keys())
                    }
                    
                    add_node_data(phase_node_id, phase_label, 'phase', phase_metadata)
                    add_edge_data(prev_element_id, phase_node_id, 'processes')
                    
                    for proc_type, proc_list in processor_groups.items():
                        group_node_id = f"{phase_node_id}_{proc_type}"
                        
                        # Sample configuration
                        sample_config = []
                        if proc_list:
                            sample_proc = proc_list[0]
                            if isinstance(sample_proc['config'], dict):
                                config_items = list(sample_proc['config'].items())[:2]
                                for key, value in config_items:
                                    if key not in ['if', 'ignore_failure']:
                                        sample_config.append(f"{key}: {str(value)[:15]}...")
                        
                        group_label = f"{proc_type}\n({len(proc_list)}x)"
                        if sample_config:
                            group_label += f"\n{', '.join(sample_config[:1])}"
                        
                        group_metadata = {
                            'processor_type': proc_type,
                            'count': len(proc_list),
                            'sample_config': sample_config
                        }
                        
                        group_detailed_info = {
                            'processors': proc_list,
                            'phase_id': phase_id
                        }
                        
                        add_node_data(group_node_id, group_label, 'processor_group', group_metadata, group_detailed_info)
                        add_edge_data(phase_node_id, group_node_id, 'contains')
                    
                    prev_element_id = phase_node_id
            
            return prev_element_id
        
        def process_relationships(item, component_type):
            if (item, component_type) in visited:
                return
            visited.add((item, component_type))
            
            node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', item)}_{component_type}"
            
            if component_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                
                # Get detailed processor information
                processor_details = []
                for processor in pipeline_info.get('processors', []):
                    proc_type = next(iter(processor.keys()))
                    proc_config = processor[proc_type]
                    processor_details.append({
                        'type': proc_type,
                        'config': proc_config
                    })
                
                # Get top processor type
                processor_types = Counter()
                for processor in pipeline_info.get('processors', []):
                    proc_type = next(iter(processor.keys()))
                    processor_types[proc_type] += 1
                
                top_processor = processor_types.most_common(1)
                
                metadata = {
                    'processor_count': processor_count,
                    'top_processor': top_processor[0][0] if top_processor else 'none',
                    'description': pipeline_info.get('description', 'No description')
                }
                
                detailed_info = {
                    'processors': processor_details,
                    'calls_pipelines': list(pipeline_info.get('calls_pipelines', set())),
                    'uses_enrich': list(pipeline_info.get('uses_enrich', set())),
                    'called_by': list(pipeline_info.get('called_by', set()))
                }
                
                # Handle different visualization levels
                if visualization_level == 'overview':
                    # Overview level: Just show basic pipeline node
                    add_node_data(node_id, item, 'pipeline', metadata, detailed_info)
                    last_node_id = node_id
                elif visualization_level == 'pipeline_detail':
                    # Pipeline detail level: Show pipeline with phases
                    add_node_data(node_id, item, 'pipeline', metadata, detailed_info)
                    last_node_id = add_pipeline_phases_interactive(item, node_id)
                elif visualization_level == 'processor_detail':
                    # Processor detail level: Show pipeline with detailed processor groups
                    add_node_data(node_id, item, 'pipeline', metadata, detailed_info)
                    last_node_id = add_processor_groups_interactive(item, node_id)
                else:
                    # Fallback to basic pipeline
                    add_node_data(node_id, item, 'pipeline', metadata, detailed_info)
                    last_node_id = node_id
                
                # Add relationships from the last node (could be pipeline, phase, or processor group)
                for target in pipeline_info.get('calls_pipelines', set()):
                    target_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', target)}_pipeline"
                    add_edge_data(last_node_id, target_id, 'calls', 'calls')
                    process_relationships(target, 'pipeline')
                
                for policy in pipeline_info.get('uses_enrich', set()):
                    policy_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', policy)}_enrich"
                    add_edge_data(last_node_id, policy_id, 'enriches with', 'enriches')
                    process_relationships(policy, 'enrich')
            
            elif component_type == 'index':
                index_info = self.infrastructure_data['indices'].get(item, {})
                pipeline_chains = len(index_info.get('pipeline_chains', []))
                
                metadata = {
                    'pipeline_chain_length': pipeline_chains,
                    'default_pipeline': index_info.get('default_pipeline'),
                    'final_pipeline': index_info.get('final_pipeline')
                }
                
                detailed_info = {
                    'pipeline_chains': index_info.get('pipeline_chains', []),
                    'settings': {
                        'default_pipeline': index_info.get('default_pipeline'),
                        'final_pipeline': index_info.get('final_pipeline')
                    }
                }
                
                add_node_data(node_id, item, 'index', metadata, detailed_info)
                
                if index_info.get('default_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', index_info['default_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'default')
                    process_relationships(index_info['default_pipeline'], 'pipeline')
                
                if index_info.get('final_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', index_info['final_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'final')
                    process_relationships(index_info['final_pipeline'], 'pipeline')
            
            elif component_type == 'enrich':
                policy_info = self.infrastructure_data['enrich_policies'].get(item, {})
                source_indices = len(policy_info.get('source_indices', []))
                used_by = len(policy_info.get('used_by_pipelines', set()))
                
                metadata = {
                    'source_count': source_indices,
                    'used_by_count': used_by,
                    'match_field': policy_info.get('match_field', 'unknown')
                }
                
                detailed_info = {
                    'source_indices': policy_info.get('source_indices', []),
                    'match_field': policy_info.get('match_field', 'unknown'),
                    'used_by_pipelines': list(policy_info.get('used_by_pipelines', set()))
                }
                
                add_node_data(node_id, item, 'enrich', metadata, detailed_info)
                
                for source_index in policy_info.get('source_indices', []):
                    index_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', source_index)}_index"
                    add_edge_data(node_id, index_id, 'source')
                    process_relationships(source_index, 'index')
        
        # Process all selected items
        for item in selected_items:
            process_relationships(item, analysis_type)
        
        return {'nodes': nodes, 'edges': edges}

    def analyze_infrastructure(self):
        """Analyze infrastructure based on selected items and visualization level."""
        selected_indices = self.selection_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select at least one item")
            return
            
        selected_items = [self.selection_list.get(i) for i in selected_indices]
        analysis_type = self.analysis_type.get()
        visualization_level = self.visualization_level.get()
        
        # Show analysis summary in text area
        summary = self.generate_analysis_summary(selected_items, analysis_type, visualization_level)
        
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, summary)
        
        self.view_btn.config(state=tk.NORMAL)

    def generate_analysis_summary(self, selected_items, analysis_type, visualization_level):
        """Generate a text summary of the analysis instead of Mermaid code."""
        summary_lines = []
        
        # Header
        level_names = {
            'overview': '📊 Overview Level',
            'pipeline_detail': '🔧 Pipeline Detail Level', 
            'processor_detail': '🔬 Processor Detail Level'
        }
        
        summary_lines.append(f"=== {level_names[visualization_level]} Analysis ===")
        summary_lines.append(f"Analysis Type: {analysis_type.title()}")
        summary_lines.append(f"Selected Items: {', '.join(selected_items)}")
        summary_lines.append("")
        
        # Analysis details
        for item in selected_items:
            summary_lines.append(f"📋 Analysis for: {item}")
            summary_lines.append("-" * 50)
            
            if analysis_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                
                summary_lines.append(f"• Total Processors: {processor_count}")
                
                if visualization_level in ['pipeline_detail', 'processor_detail']:
                    phases = self.get_pipeline_phases(item)
                    if phases:
                        summary_lines.append(f"• Processing Phases: {len(phases)}")
                        stats, total = self.get_phase_statistics(phases)
                        
                        for phase_id, phase_processors in phases.items():
                            phase_info = self.processor_phases[phase_id]
                            stat = stats.get(phase_id, {'count': 0, 'percentage': 0, 'top_processor': 'none'})
                            summary_lines.append(f"  - {phase_info['name']}: {stat['count']} processors ({stat['percentage']:.1f}%)")
                            summary_lines.append(f"    Top processor: {stat['top_processor']}")
                
                # Relationships
                if pipeline_info.get('calls_pipelines'):
                    summary_lines.append(f"• Calls Pipelines: {', '.join(pipeline_info['calls_pipelines'])}")
                
                if pipeline_info.get('uses_enrich'):
                    summary_lines.append(f"• Uses Enrichment: {', '.join(pipeline_info['uses_enrich'])}")
                
                if pipeline_info.get('called_by'):
                    summary_lines.append(f"• Called By: {', '.join(pipeline_info['called_by'])}")
            
            elif analysis_type == 'index':
                index_info = self.infrastructure_data['indices'].get(item, {})
                
                if index_info.get('default_pipeline'):
                    summary_lines.append(f"• Default Pipeline: {index_info['default_pipeline']}")
                
                if index_info.get('final_pipeline'):
                    summary_lines.append(f"• Final Pipeline: {index_info['final_pipeline']}")
                
                chain_length = len(index_info.get('pipeline_chains', []))
                summary_lines.append(f"• Pipeline Chain Length: {chain_length} steps")
                
                if index_info.get('pipeline_chains'):
                    summary_lines.append(f"• Pipeline Chain: {' → '.join(index_info['pipeline_chains'])}")
            
            elif analysis_type == 'enrich':
                policy_info = self.infrastructure_data['enrich_policies'].get(item, {})
                
                source_count = len(policy_info.get('source_indices', []))
                summary_lines.append(f"• Source Indices: {source_count}")
                
                if policy_info.get('source_indices'):
                    summary_lines.append(f"  - {', '.join(policy_info['source_indices'])}")
                
                summary_lines.append(f"• Match Field: {policy_info.get('match_field', 'unknown')}")
                
                used_by_count = len(policy_info.get('used_by_pipelines', set()))
                summary_lines.append(f"• Used by {used_by_count} pipelines")
                
                if policy_info.get('used_by_pipelines'):
                    summary_lines.append(f"  - {', '.join(policy_info['used_by_pipelines'])}")
            
            summary_lines.append("")
        
        # Instructions
        summary_lines.append("🎯 Next Steps:")
        summary_lines.append("• Click 'View Diagram' to see the interactive visualization")
        summary_lines.append("• Use the interactive features to explore relationships")
        summary_lines.append("• Hover over nodes for quick information")
        summary_lines.append("• Click nodes to see detailed information in the sidebar")
        summary_lines.append("• Double-click nodes for full processor details")
        
        return "\n".join(summary_lines)

    def generate_overview_diagram(self, selected_items, analysis_type):
        """Generate high-level overview diagram with basic statistics."""
        mermaid_code = ["graph TD"]
        visited = set()
        node_styles = set()
        
        def add_node(node_id, label, node_type, additional_info=None):
            """Helper function to add nodes with consistent formatting."""
            node_label = [label]
            
            if additional_info:
                node_label.append(additional_info)
            
            final_label = "<br/>".join(node_label)
            
            if node_type == 'index':
                mermaid_code.append(f"    {node_id}[(\"{final_label}\")]")
            elif node_type == 'pipeline':
                mermaid_code.append(f"    {node_id}[\"{final_label}\"]")
            elif node_type == 'enrich':
                mermaid_code.append(f"    {node_id}(\"{final_label}\")")
            
            node_styles.add((node_id, node_type))

        def add_relationships(item, component_type):
            if (item, component_type) in visited:
                return
            visited.add((item, component_type))
            
            node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', item)}_{component_type}"
            
            if component_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                
                # Get top processor type
                processor_types = Counter()
                for processor in pipeline_info.get('processors', []):
                    proc_type = next(iter(processor.keys()))
                    processor_types[proc_type] += 1
                
                top_processor = processor_types.most_common(1)
                top_proc_info = f"Top: {top_processor[0][0]}" if top_processor else "No processors"
                
                metadata = [
                    f"Processors: {processor_count}",
                    top_proc_info
                ]
                
                add_node(node_id, item, 'pipeline', "<br/>".join(metadata))
                
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
                metadata = [f"Pipeline chain: {pipeline_chains} steps"]
                
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
                    f"Sources: {source_indices}",
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
            "    classDef index fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;",
            "    classDef pipeline fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;",
            "    classDef enrich fill:#e8f5e8,stroke:#388e3c,stroke-width:2px;",
        ])
        
        for node_id, node_type in node_styles:
            mermaid_code.append(f"    class {node_id} {node_type};")
        
        return "\n".join(mermaid_code)

    def generate_pipeline_detail_diagram(self, selected_items, analysis_type):
        """Generate pipeline detail diagram showing logical processing phases."""
        mermaid_code = ["graph TD"]
        visited = set()
        node_styles = set()
        
        def add_node(node_id, label, node_type, additional_info=None):
            """Helper function to add nodes with consistent formatting."""
            node_label = [label]
            
            if additional_info:
                node_label.append(additional_info)
            
            final_label = "<br/>".join(node_label)
            
            if node_type == 'index':
                mermaid_code.append(f"    {node_id}[(\"{final_label}\")]")
            elif node_type == 'pipeline':
                mermaid_code.append(f"    {node_id}[\"{final_label}\"]")
            elif node_type == 'enrich':
                mermaid_code.append(f"    {node_id}(\"{final_label}\")")
            elif node_type == 'phase':
                mermaid_code.append(f"    {node_id}{{\"{final_label}\"}}")
            
            node_styles.add((node_id, node_type))

        def add_pipeline_phases(pipeline_name):
            """Add phase nodes for a pipeline and connect them."""
            phases = self.get_pipeline_phases(pipeline_name)
            
            # If no phases detected, create a generic processing phase for any processors
            if not phases:
                pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                actual_processors = [next(iter(p.keys())) for p in pipeline_info.get('processors', [])]
                if actual_processors:
                    phases = {
                        'processing': [{
                            'type': proc_type,
                            'config': {},
                            'details': []
                        } for proc_type in actual_processors]
                    }
            
            if not phases:
                return None
                
            stats, total_processors = self.get_phase_statistics(phases)
            
            pipeline_node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', pipeline_name)}_pipeline"
            prev_phase_id = None
            last_phase_id = None
            
            # Sort phases by logical order
            phase_order = ['input_parsing', 'transformation', 'enrichment', 'processing', 'formatting', 'orchestration']
            ordered_phases = [(p, phases[p]) for p in phase_order if p in phases]
            
            if not ordered_phases:
                return None
            
            for phase_id, processors in ordered_phases:
                phase_info = self.processor_phases[phase_id]
                phase_node_id = f"{pipeline_node_id}_{phase_id}"
                
                # Create phase summary
                stat = stats.get(phase_id, {'count': 0, 'percentage': 0, 'top_processor': 'none'})
                phase_label = f"{phase_info['name']}<br/>({stat['count']} processors, {stat['percentage']:.1f}%)<br/>Top: {stat['top_processor']}"
                
                add_node(phase_node_id, phase_label, 'phase')
                
                # Connect pipeline to first phase
                if prev_phase_id is None:
                    mermaid_code.append(f"    {pipeline_node_id} --> {phase_node_id}")
                else:
                    # Connect phases in sequence
                    mermaid_code.append(f"    {prev_phase_id} --> {phase_node_id}")
                
                prev_phase_id = phase_node_id
                last_phase_id = phase_node_id
                
                # Add connections to enrichment policies if this is an enrichment phase
                if phase_id == 'enrichment':
                    pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                    for policy in pipeline_info.get('uses_enrich', set()):
                        policy_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', policy)}_enrich"
                        mermaid_code.append(f"    {phase_node_id} -->|uses| {policy_id}")
                        add_relationships(policy, 'enrich')
            
            return last_phase_id  # Return the last phase node for connecting to other pipelines

        def add_relationships(item, component_type):
            if (item, component_type) in visited:
                return
            visited.add((item, component_type))
            
            node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', item)}_{component_type}"
            
            if component_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                
                metadata = [f"Total processors: {processor_count}"]
                add_node(node_id, item, 'pipeline', "<br/>".join(metadata))
                
                # Add phases for this pipeline and get the last phase node
                last_phase_node = add_pipeline_phases(item)
                
                # Connect to other pipelines from the last phase (or pipeline node if no phases)
                connection_node = last_phase_node if last_phase_node else node_id
                
                for target in pipeline_info.get('calls_pipelines', set()):
                    target_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', target)}_pipeline"
                    mermaid_code.append(f"    {connection_node} -->|calls| {target_id}")
                    add_relationships(target, 'pipeline')
            
            elif component_type == 'index':
                index_info = self.infrastructure_data['indices'].get(item, {})
                pipeline_chains = len(index_info.get('pipeline_chains', []))
                metadata = [f"Pipeline chain: {pipeline_chains} steps"]
                
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
                
                metadata = [f"Sources: {source_indices}"]
                add_node(node_id, item, 'enrich', "<br/>".join(metadata))
                
                for source_index in policy_info.get('source_indices', []):
                    index_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', source_index)}_index"
                    mermaid_code.append(f"    {node_id} -->|source| {index_id}")
                    add_relationships(source_index, 'index')
        
        for item in selected_items:
            add_relationships(item, analysis_type)
        
        mermaid_code.extend([
            "    classDef index fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;",
            "    classDef pipeline fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;",
            "    classDef enrich fill:#e8f5e8,stroke:#388e3c,stroke-width:2px;",
            "    classDef phase fill:#fff3e0,stroke:#f57c00,stroke-width:2px;",
        ])
        
        for node_id, node_type in node_styles:
            mermaid_code.append(f"    class {node_id} {node_type};")
        
        return "\n".join(mermaid_code)

    def generate_processor_detail_diagram(self, selected_items, analysis_type):
        """Generate detailed processor diagram showing individual processor groups."""
        mermaid_code = ["graph TD"]
        visited = set()
        node_styles = set()
        
        def add_node(node_id, label, node_type, additional_info=None):
            """Helper function to add nodes with consistent formatting."""
            node_label = [label]
            
            if additional_info:
                node_label.append(additional_info)
            
            final_label = "<br/>".join(node_label)
            
            if node_type == 'index':
                mermaid_code.append(f"    {node_id}[(\"{final_label}\")]")
            elif node_type == 'pipeline':
                mermaid_code.append(f"    {node_id}[\"{final_label}\"]")
            elif node_type == 'enrich':
                mermaid_code.append(f"    {node_id}(\"{final_label}\")")
            elif node_type == 'phase':
                mermaid_code.append(f"    {node_id}{{\"{final_label}\"}}")
            elif node_type == 'processor_group':
                mermaid_code.append(f"    {node_id}[[\"{final_label}\"]]")
            
            node_styles.add((node_id, node_type))

        def add_processor_groups(pipeline_name):
            """Add detailed processor group nodes for a pipeline."""
            phases = self.get_pipeline_phases(pipeline_name)
            pipeline_node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', pipeline_name)}_pipeline"
            
            phase_order = ['input_parsing', 'transformation', 'enrichment', 'processing', 'formatting', 'orchestration']
            ordered_phases = [(p, phases[p]) for p in phase_order if p in phases]
            
            prev_element_id = pipeline_node_id
            
            for phase_id, processors in ordered_phases:
                phase_info = self.processor_phases[phase_id]
                phase_node_id = f"{pipeline_node_id}_{phase_id}"
                
                # Group processors by type within this phase
                processor_groups = defaultdict(list)
                for processor in processors:
                    processor_groups[processor['type']].append(processor)
                
                if len(processor_groups) == 1:
                    # Single processor type - create one group node
                    proc_type = list(processor_groups.keys())[0]
                    group_node_id = f"{phase_node_id}_{proc_type}"
                    
                    # Sample configuration from first processor
                    sample_config = []
                    if processor_groups[proc_type]:
                        sample_proc = processor_groups[proc_type][0]
                        if isinstance(sample_proc['config'], dict):
                            # Show up to 3 key configuration items
                            config_items = list(sample_proc['config'].items())[:3]
                            for key, value in config_items:
                                if key not in ['if', 'ignore_failure']:
                                    sample_config.append(f"{key}: {str(value)[:20]}...")
                    
                    group_label = f"{phase_info['name']}<br/>{proc_type} ({len(processor_groups[proc_type])}x)"
                    if sample_config:
                        group_label += f"<br/>Config: {', '.join(sample_config[:2])}"
                    
                    add_node(group_node_id, group_label, 'processor_group')
                    mermaid_code.append(f"    {prev_element_id} --> {group_node_id}")
                    prev_element_id = group_node_id
                    
                else:
                    # Multiple processor types - create phase node and individual groups
                    phase_label = f"{phase_info['name']}<br/>({len(processors)} processors)"
                    add_node(phase_node_id, phase_label, 'phase')
                    mermaid_code.append(f"    {prev_element_id} --> {phase_node_id}")
                    
                    for proc_type, proc_list in processor_groups.items():
                        group_node_id = f"{phase_node_id}_{proc_type}"
                        
                        # Sample configuration
                        sample_config = []
                        if proc_list:
                            sample_proc = proc_list[0]
                            if isinstance(sample_proc['config'], dict):
                                config_items = list(sample_proc['config'].items())[:2]
                                for key, value in config_items:
                                    if key not in ['if', 'ignore_failure']:
                                        sample_config.append(f"{key}: {str(value)[:15]}...")
                        
                        group_label = f"{proc_type}<br/>({len(proc_list)}x)"
                        if sample_config:
                            group_label += f"<br/>{', '.join(sample_config)}"
                        
                        add_node(group_node_id, group_label, 'processor_group')
                        mermaid_code.append(f"    {phase_node_id} --> {group_node_id}")
                    
                    prev_element_id = phase_node_id
                
                # Add connections to external resources
                if phase_id == 'enrichment':
                    pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                    for policy in pipeline_info.get('uses_enrich', set()):
                        policy_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', policy)}_enrich"
                        mermaid_code.append(f"    {prev_element_id} -->|uses| {policy_id}")
                        add_relationships(policy, 'enrich')
                
                if phase_id == 'orchestration':
                    pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                    for target in pipeline_info.get('calls_pipelines', set()):
                        target_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', target)}_pipeline"
                        mermaid_code.append(f"    {prev_element_id} -->|calls| {target_id}")
                        add_relationships(target, 'pipeline')

        def add_relationships(item, component_type):
            if (item, component_type) in visited:
                return
            visited.add((item, component_type))
            
            node_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', item)}_{component_type}"
            
            if component_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                
                metadata = [f"Total processors: {processor_count}"]
                add_node(node_id, item, 'pipeline', "<br/>".join(metadata))
                
                # Add detailed processor groups for this pipeline
                add_processor_groups(item)
            
            elif component_type == 'index':
                index_info = self.infrastructure_data['indices'].get(item, {})
                pipeline_chains = len(index_info.get('pipeline_chains', []))
                metadata = [f"Pipeline chain: {pipeline_chains} steps"]
                
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
                
                metadata = [f"Sources: {source_indices}"]
                add_node(node_id, item, 'enrich', "<br/>".join(metadata))
                
                for source_index in policy_info.get('source_indices', []):
                    index_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', source_index)}_index"
                    mermaid_code.append(f"    {node_id} -->|source| {index_id}")
                    add_relationships(source_index, 'index')
        
        for item in selected_items:
            add_relationships(item, analysis_type)
        
        mermaid_code.extend([
            "    classDef index fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;",
            "    classDef pipeline fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;",
            "    classDef enrich fill:#e8f5e8,stroke:#388e3c,stroke-width:2px;",
            "    classDef phase fill:#fff3e0,stroke:#f57c00,stroke-width:2px;",
            "    classDef processor_group fill:#fce4ec,stroke:#c2185b,stroke-width:1px;",
        ])
        
        for node_id, node_type in node_styles:
            mermaid_code.append(f"    class {node_id} {node_type};")
        
        return "\n".join(mermaid_code)

    def view_diagram(self):
        """View the current diagram in a browser window with interactive features."""
        selected_indices = self.selection_list.curselection()
        if not selected_indices:
            messagebox.showwarning("Warning", "Please select at least one item")
            return
            
        selected_items = [self.selection_list.get(i) for i in selected_indices]
        analysis_type = self.analysis_type.get()
        visualization_level = self.visualization_level.get()
        
        # Generate interactive data
        graph_data = self.generate_interactive_data(selected_items, analysis_type)
        
        # Create level-specific legend content
        level_info = {
            "overview": {
                "title": "📊 Overview Level",
                "description": "High-level pipeline relationships with basic statistics",
                "legend_items": [
                    ("index", "#e1f5fe", "Index (Database shape)"),
                    ("pipeline", "#f3e5f5", "Pipeline (Rectangle)"),
                    ("enrich", "#e8f5e8", "Enrichment Policy (Rounded Rectangle)")
                ]
            },
            "pipeline_detail": {
                "title": "🔧 Pipeline Detail Level", 
                "description": "Logical processing phases within pipelines",
                "legend_items": [
                    ("index", "#e1f5fe", "Index (Database shape)"),
                    ("pipeline", "#f3e5f5", "Pipeline (Rectangle)"),
                    ("enrich", "#e8f5e8", "Enrichment Policy (Rounded Rectangle)"),
                    ("phase", "#fff3e0", "Processing Phase (Diamond)")
                ]
            },
            "processor_detail": {
                "title": "🔬 Processor Detail Level",
                "description": "Detailed processor groups within each phase",
                "legend_items": [
                    ("index", "#e1f5fe", "Index (Database shape)"),
                    ("pipeline", "#f3e5f5", "Pipeline (Rectangle)"),
                    ("enrich", "#e8f5e8", "Enrichment Policy (Rounded Rectangle)"),
                    ("phase", "#fff3e0", "Processing Phase (Diamond)"),
                    ("processor_group", "#fce4ec", "Processor Group (Stadium)")
                ]
            }
        }
        
        current_level = level_info[visualization_level]
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Elasticsearch Pipeline Relationships - {current_level['title']} (Interactive)</title>
            <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js"></script>
            <script>
                // Graph data from Python
                const graphData = {json.dumps(graph_data, indent=2)};
                
                let network;
                let selectedNode = null;
                let animationRunning = false;
                let animationInterval = null;
                let particles = [];
                
                // Initialize the network
                function initNetwork() {{
                    const container = document.getElementById('network');
                    
                    const options = {{
                        nodes: {{
                            borderWidth: 2,
                            shadow: true,
                            font: {{
                                size: 14,
                                face: 'Arial'
                            }},
                            margin: 15,
                            widthConstraint: {{
                                minimum: 120,
                                maximum: 220
                            }}
                        }},
                        edges: {{
                            width: 2,
                            shadow: true,
                            smooth: {{
                                type: 'continuous'
                            }},
                            font: {{
                                size: 12,
                                align: 'middle'
                            }},
                            length: 200
                        }},
                        physics: {{
                            enabled: true,
                            stabilization: {{
                                iterations: 150,
                                updateInterval: 25
                            }},
                            barnesHut: {{
                                gravitationalConstant: -4000,
                                centralGravity: 0.1,
                                springLength: 200,
                                springConstant: 0.02,
                                damping: 0.15,
                                avoidOverlap: 0.5
                            }}
                        }},
                        interaction: {{
                            hover: true,
                            tooltipDelay: 300,
                            hideEdgesOnDrag: false,
                            dragNodes: true,
                            dragView: true,
                            zoomView: true
                        }},
                        layout: {{
                            improvedLayout: true,
                            randomSeed: 42,
                            hierarchical: false
                        }}
                    }};
                    
                    network = new vis.Network(container, graphData, options);
                    
                    // Add event listeners
                    network.on('hoverNode', onHoverNode);
                    network.on('blurNode', onBlurNode);
                    network.on('click', onClick);
                    network.on('doubleClick', onDoubleClick);
                }}
                
                // Hover event handler
                function onHoverNode(event) {{
                    const nodeId = event.node;
                    const node = graphData.nodes.find(n => n.id === nodeId);
                    
                    if (node) {{
                        showTooltip(event.pointer.DOM, node);
                    }}
                }}
                
                // Blur event handler
                function onBlurNode(event) {{
                    hideTooltip();
                }}
                
                // Click event handler with delay to allow double-click detection
                let clickTimeout = null;
                function onClick(event) {{
                    // Clear any existing timeout
                    if (clickTimeout) {{
                        clearTimeout(clickTimeout);
                        clickTimeout = null;
                        return; // This was part of a double-click, don't process single click
                    }}
                    
                    // Set a timeout to process single click after double-click window
                    clickTimeout = setTimeout(() => {{
                        if (event.nodes.length > 0) {{
                            const nodeId = event.nodes[0];
                            const node = graphData.nodes.find(n => n.id === nodeId);
                            
                            if (node) {{
                                selectNode(node);
                            }}
                        }} else {{
                            clearSelection();
                        }}
                        clickTimeout = null;
                    }}, 250); // 250ms delay to allow double-click detection
                }}
                
                // Double click event handler
                function onDoubleClick(event) {{
                    // Clear the single click timeout since this is a double-click
                    if (clickTimeout) {{
                        clearTimeout(clickTimeout);
                        clickTimeout = null;
                    }}
                    
                    if (event.nodes.length > 0) {{
                        const nodeId = event.nodes[0];
                        const node = graphData.nodes.find(n => n.id === nodeId);
                        
                        if (node) {{
                            console.log('Double-click detected on node:', node.label); // Debug log
                            showDetailModal(node);
                        }}
                    }}
                }}
                
                // Show tooltip
                function showTooltip(position, node) {{
                    const tooltip = document.getElementById('tooltip');
                    const metadata = node.metadata || {{}};
                    
                    let content = `<strong>${{node.label}}</strong><br/>`;
                    content += `<em>Type: ${{node.type}}</em><br/><br/>`;
                    
                    if (node.type === 'pipeline') {{
                        content += `Processors: ${{metadata.processor_count || 0}}<br/>`;
                        content += `Top Processor: ${{metadata.top_processor || 'none'}}<br/>`;
                        if (metadata.description) {{
                            content += `Description: ${{metadata.description.substring(0, 50)}}...<br/>`;
                        }}
                    }} else if (node.type === 'index') {{
                        content += `Pipeline Chain: ${{metadata.pipeline_chain_length || 0}} steps<br/>`;
                        if (metadata.default_pipeline) {{
                            content += `Default Pipeline: ${{metadata.default_pipeline}}<br/>`;
                        }}
                        if (metadata.final_pipeline) {{
                            content += `Final Pipeline: ${{metadata.final_pipeline}}<br/>`;
                        }}
                    }} else if (node.type === 'enrich') {{
                        content += `Source Indices: ${{metadata.source_count || 0}}<br/>`;
                        content += `Used by Pipelines: ${{metadata.used_by_count || 0}}<br/>`;
                        content += `Match Field: ${{metadata.match_field || 'unknown'}}<br/>`;
                    }}
                    
                    content += `<br/><small>💡 Click to select, double-click for details</small>`;
                    
                    tooltip.innerHTML = content;
                    tooltip.style.left = (position.x + 10) + 'px';
                    tooltip.style.top = (position.y - 10) + 'px';
                    tooltip.style.display = 'block';
                }}
                
                // Hide tooltip
                function hideTooltip() {{
                    const tooltip = document.getElementById('tooltip');
                    tooltip.style.display = 'none';
                }}
                
                // Select node
                function selectNode(node) {{
                    selectedNode = node;
                    updateSidebar(node);
                    
                    // Highlight connected nodes
                    const connectedNodes = network.getConnectedNodes(node.id);
                    const connectedEdges = network.getConnectedEdges(node.id);
                    
                    network.selectNodes([node.id]);
                    network.selectEdges(connectedEdges);
                }}
                
                // Clear selection
                function clearSelection() {{
                    selectedNode = null;
                    updateSidebar(null);
                    network.unselectAll();
                }}
                
                // Update sidebar with node information
                function updateSidebar(node) {{
                    const sidebar = document.getElementById('sidebar');
                    
                    if (!node) {{
                        sidebar.innerHTML = `
                            <div class="sidebar-content">
                                <h3>📋 Node Information</h3>
                                <p>Click on a node to see detailed information</p>
                                <div class="help-text">
                                    <h4>💡 Interaction Guide:</h4>
                                    <ul>
                                        <li><strong>Hover:</strong> Quick info tooltip</li>
                                        <li><strong>Click:</strong> Select and highlight connections</li>
                                        <li><strong>Double-click:</strong> Detailed information modal</li>
                                        <li><strong>Drag:</strong> Reposition nodes</li>
                                    </ul>
                                </div>
                            </div>
                        `;
                        return;
                    }}
                    
                    const metadata = node.metadata || {{}};
                    const detailedInfo = node.detailed_info || {{}};
                    
                    let content = `
                        <div class="sidebar-content">
                            <h3>${{node.label}}</h3>
                            <div class="node-type-badge node-type-${{node.type}}">${{node.type.toUpperCase()}}</div>
                    `;
                    
                    if (node.type === 'pipeline') {{
                        content += `
                            <div class="info-section">
                                <h4>📊 Statistics</h4>
                                <div class="stat-item">Processors: <strong>${{metadata.processor_count || 0}}</strong></div>
                                <div class="stat-item">Top Processor: <strong>${{metadata.top_processor || 'none'}}</strong></div>
                            </div>
                        `;
                        
                        if (metadata.description) {{
                            content += `
                                <div class="info-section">
                                    <h4>📝 Description</h4>
                                    <p>${{metadata.description}}</p>
                                </div>
                            `;
                        }}
                        
                        if (detailedInfo.calls_pipelines && detailedInfo.calls_pipelines.length > 0) {{
                            content += `
                                <div class="info-section">
                                    <h4>🔗 Calls Pipelines</h4>
                                    <ul>${{detailedInfo.calls_pipelines.map(p => `<li>${{p}}</li>`).join('')}}</ul>
                                </div>
                            `;
                        }}
                        
                        if (detailedInfo.uses_enrich && detailedInfo.uses_enrich.length > 0) {{
                            content += `
                                <div class="info-section">
                                    <h4>📈 Uses Enrichment</h4>
                                    <ul>${{detailedInfo.uses_enrich.map(e => `<li>${{e}}</li>`).join('')}}</ul>
                                </div>
                            `;
                        }}
                        
                        if (detailedInfo.called_by && detailedInfo.called_by.length > 0) {{
                            content += `
                                <div class="info-section">
                                    <h4>⬅️ Called By</h4>
                                    <ul>${{detailedInfo.called_by.map(p => `<li>${{p}}</li>`).join('')}}</ul>
                                </div>
                            `;
                        }}
                    }} else if (node.type === 'index') {{
                        content += `
                            <div class="info-section">
                                <h4>📊 Pipeline Configuration</h4>
                                <div class="stat-item">Chain Length: <strong>${{metadata.pipeline_chain_length || 0}} steps</strong></div>
                        `;
                        
                        if (metadata.default_pipeline) {{
                            content += `<div class="stat-item">Default Pipeline: <strong>${{metadata.default_pipeline}}</strong></div>`;
                        }}
                        
                        if (metadata.final_pipeline) {{
                            content += `<div class="stat-item">Final Pipeline: <strong>${{metadata.final_pipeline}}</strong></div>`;
                        }}
                        
                        content += `</div>`;
                        
                        if (detailedInfo.pipeline_chains && detailedInfo.pipeline_chains.length > 0) {{
                            content += `
                                <div class="info-section">
                                    <h4>🔗 Pipeline Chain</h4>
                                    <ol>${{detailedInfo.pipeline_chains.map(p => `<li>${{p}}</li>`).join('')}}</ol>
                                </div>
                            `;
                        }}
                    }} else if (node.type === 'enrich') {{
                        content += `
                            <div class="info-section">
                                <h4>📊 Enrichment Statistics</h4>
                                <div class="stat-item">Source Indices: <strong>${{metadata.source_count || 0}}</strong></div>
                                <div class="stat-item">Used by Pipelines: <strong>${{metadata.used_by_count || 0}}</strong></div>
                                <div class="stat-item">Match Field: <strong>${{metadata.match_field || 'unknown'}}</strong></div>
                            </div>
                        `;
                        
                        if (detailedInfo.source_indices && detailedInfo.source_indices.length > 0) {{
                            content += `
                                <div class="info-section">
                                    <h4>📥 Source Indices</h4>
                                    <ul>${{detailedInfo.source_indices.map(i => `<li>${{i}}</li>`).join('')}}</ul>
                                </div>
                            `;
                        }}
                        
                        if (detailedInfo.used_by_pipelines && detailedInfo.used_by_pipelines.length > 0) {{
                            content += `
                                <div class="info-section">
                                    <h4>🔗 Used by Pipelines</h4>
                                    <ul>${{detailedInfo.used_by_pipelines.map(p => `<li>${{p}}</li>`).join('')}}</ul>
                                </div>
                            `;
                        }}
                    }}
                    
                    content += `
                            <div class="action-buttons">
                                <button onclick="showDetailModal(selectedNode)" class="detail-btn">🔍 View Full Details</button>
                                <button onclick="focusOnNode('${{node.id}}')" class="focus-btn">🎯 Focus on Node</button>
                            </div>
                        </div>
                    `;
                    
                    sidebar.innerHTML = content;
                }}
                
                // Show detailed modal
                function showDetailModal(node) {{
                    const modal = document.getElementById('detailModal');
                    const modalContent = document.getElementById('modalContent');
                    
                    const detailedInfo = node.detailed_info || {{}};
                    
                    let content = `
                        <h2>${{node.label}} - Detailed Information</h2>
                        <div class="node-type-badge node-type-${{node.type}}">${{node.type.toUpperCase()}}</div>
                    `;
                    
                    if (node.type === 'pipeline' && detailedInfo.processors) {{
                        content += `
                            <div class="detail-section">
                                <h3>🔧 Processors (${{detailedInfo.processors.length}})</h3>
                                <div class="processor-list">
                        `;
                        
                        detailedInfo.processors.forEach((proc, index) => {{
                            content += `
                                <div class="processor-item">
                                    <h4>${{index + 1}}. ${{proc.type}}</h4>
                                    <div class="processor-config">
                                        <pre>${{JSON.stringify(proc.config, null, 2)}}</pre>
                                    </div>
                                </div>
                            `;
                        }});
                        
                        content += `
                                </div>
                            </div>
                        `;
                    }} else if (node.type === 'phase' && detailedInfo.processors) {{
                        // Show the phase's processor details
                        content += `
                            <div class="detail-section">
                                <h3>🔧 Processors in this Phase (${{detailedInfo.processors.length}})</h3>
                                <div class="processor-types">
                                    <h4>Processor Types</h4>
                                    <ul>
                        `;
                        
                        // Show processor type distribution
                        if (detailedInfo.processor_types) {{
                            Object.entries(detailedInfo.processor_types).forEach(([type, count]) => {{
                                content += `<li>${{type}}: ${{count}}x</li>`;
                            }});
                        }}
                        
                        content += `
                                    </ul>
                                </div>
                                <div class="processor-list">
                        `;
                        
                        detailedInfo.processors.forEach((proc, index) => {{
                            content += `
                                <div class="processor-item">
                                    <h4>${{index + 1}}. ${{proc.type}}</h4>
                                    <div class="processor-config">
                                        <pre>${{JSON.stringify(proc.config, null, 2)}}</pre>
                                    </div>
                                    ${{proc.details && proc.details.length > 0 ? 
                                        `<div class="processor-details">
                                            <h5>Configuration Details:</h5>
                                            <ul>${{proc.details.map(d => `<li>${{d}}</li>`).join('')}}</ul>
                                        </div>` 
                                        : ''}}
                                </div>
                            `;
                        }});
                        
                        content += `
                                </div>
                                ${{detailedInfo.phase_description ? 
                                    `<div class="phase-description">
                                        <h4>Phase Description</h4>
                                        <p>${{detailedInfo.phase_description}}</p>
                                    </div>` 
                                    : ''}}
                            </div>
                        `;
                    }} else if (node.type === 'processor_group' && detailedInfo.processors) {{
                        // Show the processor group's details
                        content += `
                            <div class="detail-section">
                                <h3>🔧 Processors in this Group (${{detailedInfo.processors.length}})</h3>
                                <div class="processor-list">
                        `;
                        
                        detailedInfo.processors.forEach((proc, index) => {{
                            content += `
                                <div class="processor-item">
                                    <h4>${{index + 1}}. ${{proc.type}}</h4>
                                    <div class="processor-config">
                                        <pre>${{JSON.stringify(proc.config, null, 2)}}</pre>
                                    </div>
                                </div>
                            `;
                        }});
                        
                        content += `
                                </div>
                            </div>
                        `;
                    }}
                    
                    content += `
                        <div class="modal-actions">
                            <button onclick="closeModal()" class="close-btn">Close</button>
                        </div>
                    `;
                    
                    modalContent.innerHTML = content;
                    modal.style.display = 'block';
                }}
                
                // Close modal
                function closeModal() {{
                    const modal = document.getElementById('detailModal');
                    modal.style.display = 'none';
                }}
                
                // Focus on node
                function focusOnNode(nodeId) {{
                    network.focus(nodeId, {{
                        scale: 1.5,
                        animation: {{
                            duration: 1000,
                            easingFunction: 'easeInOutQuad'
                        }}
                    }});
                }}
                
                // Data flow animation functions
                function createParticle(edgeId, fromPos, toPos, color = '#00ff00') {{
                    return {{
                        id: Math.random().toString(36).substr(2, 9),
                        edgeId: edgeId,
                        fromPos: fromPos,
                        toPos: toPos,
                        currentPos: {{ x: fromPos.x, y: fromPos.y }},
                        progress: 0,
                        color: color,
                        size: 4,
                        speed: 0.02 + Math.random() * 0.01, // Vary speed slightly
                        life: 1.0
                    }};
                }}
                
                function updateParticles() {{
                    const canvas = network.canvas.frame.canvas;
                    const ctx = canvas.getContext('2d');
                    
                    // Update particle positions
                    particles = particles.filter(particle => {{
                        particle.progress += particle.speed;
                        
                        if (particle.progress >= 1.0) {{
                            return false; // Remove completed particles
                        }}
                        
                        // Interpolate position along the edge
                        const t = particle.progress;
                        particle.currentPos.x = particle.fromPos.x + (particle.toPos.x - particle.fromPos.x) * t;
                        particle.currentPos.y = particle.fromPos.y + (particle.toPos.y - particle.fromPos.y) * t;
                        
                        return true;
                    }});
                    
                    // Draw particles
                    particles.forEach(particle => {{
                        ctx.save();
                        ctx.globalAlpha = particle.life;
                        ctx.fillStyle = particle.color;
                        ctx.beginPath();
                        ctx.arc(particle.currentPos.x, particle.currentPos.y, particle.size, 0, 2 * Math.PI);
                        ctx.fill();
                        
                        // Add glow effect
                        ctx.shadowColor = particle.color;
                        ctx.shadowBlur = 10;
                        ctx.beginPath();
                        ctx.arc(particle.currentPos.x, particle.currentPos.y, particle.size * 0.5, 0, 2 * Math.PI);
                        ctx.fill();
                        ctx.restore();
                    }});
                }}
                
                function spawnParticles() {{
                    if (!animationRunning) return;
                    
                    // Use the graph data directly instead of network methods
                    graphData.edges.forEach(edge => {{
                        // Get node positions using the correct vis.js API
                        const nodePositions = network.getPositions([edge.from, edge.to]);
                        const fromPos = nodePositions[edge.from];
                        const toPos = nodePositions[edge.to];
                        
                        if (!fromPos || !toPos) return;
                        
                        // Convert to canvas coordinates
                        const fromCanvas = network.canvasToDOM(fromPos);
                        const toCanvas = network.canvasToDOM(toPos);
                        
                        // Determine particle color based on edge type
                        let particleColor = '#00ff00'; // Default green
                        if (edge.type === 'calls') {{
                            particleColor = '#ff9800'; // Orange for pipeline calls
                        }} else if (edge.type === 'enriches') {{
                            particleColor = '#4caf50'; // Green for enrichment
                        }} else {{
                            particleColor = '#2196f3'; // Blue for default relationships
                        }}
                        
                        // Spawn particle with some randomness
                        if (Math.random() < 0.3) {{ // 30% chance to spawn
                            const edgeId = edge.from + '-' + edge.to;
                            particles.push(createParticle(edgeId, fromCanvas, toCanvas, particleColor));
                        }}
                    }});
                }}
                
                function startDataFlowAnimation() {{
                    if (animationRunning) return;
                    
                    animationRunning = true;
                    particles = [];
                    
                    // Start animation loop
                    animationInterval = setInterval(() => {{
                        updateParticles();
                        spawnParticles();
                        network.redraw(); // Trigger redraw to show particles
                    }}, 50); // 20 FPS
                    
                    // Update button state
                    const flowBtn = document.querySelector('.flow-btn');
                    if (flowBtn) {{
                        flowBtn.textContent = '⏸️ Stop Flow';
                        flowBtn.onclick = stopDataFlowAnimation;
                    }}
                }}
                
                function stopDataFlowAnimation() {{
                    if (!animationRunning) return;
                    
                    animationRunning = false;
                    particles = [];
                    
                    if (animationInterval) {{
                        clearInterval(animationInterval);
                        animationInterval = null;
                    }}
                    
                    network.redraw(); // Clear particles
                    
                    // Update button state
                    const flowBtn = document.querySelector('.flow-btn');
                    if (flowBtn) {{
                        flowBtn.textContent = '▶️ Show Data Flow';
                        flowBtn.onclick = startDataFlowAnimation;
                    }}
                }}
                
                function toggleDataFlowAnimation() {{
                    if (animationRunning) {{
                        stopDataFlowAnimation();
                    }} else {{
                        startDataFlowAnimation();
                    }}
                }}
                
                // Export functionality
                async function exportAsPNG() {{
                    try {{
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        const networkCanvas = network.canvas.frame.canvas;
                        
                        // Set canvas size
                        canvas.width = networkCanvas.width;
                        canvas.height = networkCanvas.height;
                        
                        // Fill with white background
                        ctx.fillStyle = 'white';
                        ctx.fillRect(0, 0, canvas.width, canvas.height);
                        
                        // Draw the network
                        ctx.drawImage(networkCanvas, 0, 0);
                        
                        // Convert to blob and save
                        canvas.toBlob((blob) => {{
                            const link = document.createElement('a');
                            link.download = 'pipeline_diagram.png';
                            link.href = URL.createObjectURL(blob);
                            link.click();
                        }}, 'image/png');
                    }} catch (error) {{
                        alert('Failed to export PNG: ' + error.message);
                    }}
                }}
                
                function exportAsSVG() {{
                    try {{
                        // Create SVG representation
                        const svgData = `
                            <svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
                                <text x="400" y="300" text-anchor="middle" font-family="Arial" font-size="16">
                                    SVG export not fully implemented for vis.js networks.
                                    Please use PNG export instead.
                                </text>
                            </svg>
                        `;
                        
                        const blob = new Blob([svgData], {{type: 'image/svg+xml'}});
                        const link = document.createElement('a');
                        link.download = 'pipeline_diagram.svg';
                        link.href = URL.createObjectURL(blob);
                        link.click();
                    }} catch (error) {{
                        alert('Failed to export SVG: ' + error.message);
                    }}
                }}
                
                // Override network's redraw to include particles
                let originalRedraw;
                
                function setupParticleRendering() {{
                    if (network && !originalRedraw) {{
                        originalRedraw = network.redraw.bind(network);
                        network.redraw = function() {{
                            originalRedraw();
                            if (animationRunning) {{
                                updateParticles();
                            }}
                        }};
                    }}
                }}
                
                // Toggle expandable text functionality
                function toggleExpandableText(element) {{
                    const fullText = element.getAttribute('data-full-text');
                    const count = element.getAttribute('data-count');
                    const isExpanded = element.classList.contains('expanded');
                    
                    if (isExpanded) {{
                        // Collapse
                        element.innerHTML = `(+ ${{count}} more)`;
                        element.classList.remove('expanded');
                        element.title = `Click to expand: ${{fullText}}`;
                    }} else {{
                        // Expand
                        element.innerHTML = `, ${{fullText}} <span class="collapse-indicator">(click to collapse)</span>`;
                        element.classList.add('expanded');
                        element.title = 'Click to collapse';
                    }}
                }}
                
                // Initialize when page loads
                window.addEventListener('load', () => {{
                    initNetwork();
                    // Setup particle rendering after network is initialized
                    setTimeout(setupParticleRendering, 1000);
                }});
            </script>
            <style>
                body {{
                    margin: 20px;
                    font-family: Arial, sans-serif;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .header {{
                    margin-bottom: 20px;
                    padding-bottom: 15px;
                    border-bottom: 2px solid #eee;
                }}
                .level-badge {{
                    display: inline-block;
                    padding: 5px 15px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border-radius: 20px;
                    font-size: 0.9em;
                    margin-bottom: 10px;
                }}
                .mermaid {{
                    background: white;
                    padding: 20px;
                    border-radius: 4px;
                    overflow: auto;
                    transform-origin: center;
                    transition: transform 0.2s;
                    border: 1px solid #ddd;
                }}
                .legend {{
                    margin-top: 20px;
                    padding-top: 20px;
                    border-top: 1px solid #eee;
                    display: grid;
                    grid-template-columns: 1fr 1fr;
                    gap: 20px;
                }}
                .legend-section {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 6px;
                }}
                .legend-item {{
                    display: flex;
                    align-items: center;
                    margin-bottom: 8px;
                }}
                .legend-color {{
                    width: 20px;
                    height: 20px;
                    margin-right: 10px;
                    border: 1px solid #333;
                    border-radius: 3px;
                }}
                .phase-info {{
                    background: #fff3e0;
                    padding: 15px;
                    border-radius: 6px;
                    margin-top: 15px;
                }}
                .phase-category {{
                    display: inline-block;
                    margin: 5px 10px 5px 0;
                    padding: 3px 8px;
                    background-color: #e3f2fd;
                    border-radius: 12px;
                    font-size: 0.85em;
                }}

                .zoom-controls {{
                    position: fixed;
                    top: 50%;
                    right: 20px;
                    transform: translateY(-50%);
                    background: white;
                    padding: 10px;
                    border-radius: 6px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                    z-index: 1000;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }}

                .export-controls {{
                    position: fixed;
                    top: 50%;
                    left: 20px;
                    transform: translateY(-50%);
                    background: white;
                    padding: 10px;
                    border-radius: 6px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                    z-index: 1000;
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                }}

                .zoom-btn, .export-btn {{
                    margin: 0;
                    padding: 8px 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: #f8f8f8;
                    cursor: pointer;
                    font-size: 0.9em;
                    white-space: nowrap;
                    text-align: center;
                    min-width: 120px;
                }}

                .zoom-btn:hover, .export-btn:hover {{
                    background: #e8e8e8;
                    border-color: #999;
                }}

                .relationship-types {{
                    margin-top: 15px;
                }}
                .relationship-type {{
                    display: inline-block;
                    margin: 5px 15px 5px 0;
                    padding: 5px 10px;
                    background-color: #f0f0f0;
                    border-radius: 4px;
                    font-size: 0.85em;
                    border-left: 3px solid #2196f3;
                }}
                
                /* Interactive visualization styles */
                .main-content {{
                    display: flex;
                    height: 600px;
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                
                .network-container {{
                    flex: 1;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    background: white;
                }}
                
                .sidebar {{
                    width: 300px;
                    border: 1px solid #ddd;
                    border-radius: 6px;
                    background: #f8f9fa;
                    overflow-y: auto;
                }}
                
                .sidebar-content {{
                    padding: 15px;
                }}
                
                .sidebar h3 {{
                    margin-top: 0;
                    color: #333;
                }}
                
                .node-type-badge {{
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 12px;
                    font-size: 0.8em;
                    font-weight: bold;
                    margin-bottom: 10px;
                }}
                
                .node-type-index {{
                    background: #e1f5fe;
                    color: #0277bd;
                }}
                
                .node-type-pipeline {{
                    background: #f3e5f5;
                    color: #7b1fa2;
                }}
                
                .node-type-enrich {{
                    background: #e8f5e8;
                    color: #388e3c;
                }}
                
                .node-type-phase {{
                    background: #fff3e0;
                    color: #f57c00;
                }}
                
                .node-type-processor_group {{
                    background: #fce4ec;
                    color: #c2185b;
                }}
                
                .info-section {{
                    margin-bottom: 15px;
                    padding: 10px;
                    background: white;
                    border-radius: 4px;
                    border-left: 3px solid #2196f3;
                }}
                
                .info-section h4 {{
                    margin: 0 0 8px 0;
                    color: #333;
                    font-size: 0.9em;
                }}
                
                .stat-item {{
                    margin-bottom: 5px;
                    font-size: 0.85em;
                }}
                
                .info-section ul, .info-section ol {{
                    margin: 5px 0;
                    padding-left: 20px;
                }}
                
                .info-section li {{
                    margin-bottom: 3px;
                    font-size: 0.85em;
                }}
                
                .action-buttons {{
                    margin-top: 15px;
                    display: flex;
                    gap: 10px;
                    flex-direction: column;
                }}
                
                .detail-btn, .focus-btn {{
                    padding: 8px 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: #2196f3;
                    color: white;
                    cursor: pointer;
                    font-size: 0.85em;
                    text-align: center;
                }}
                
                .detail-btn:hover, .focus-btn:hover {{
                    background: #1976d2;
                }}
                
                .help-text {{
                    margin-top: 15px;
                    padding: 10px;
                    background: #e3f2fd;
                    border-radius: 4px;
                }}
                
                .help-text h4 {{
                    margin: 0 0 8px 0;
                    font-size: 0.9em;
                }}
                
                .help-text ul {{
                    margin: 0;
                    padding-left: 20px;
                }}
                
                .help-text li {{
                    margin-bottom: 5px;
                    font-size: 0.8em;
                }}
                
                /* Tooltip styles */
                .tooltip {{
                    position: absolute;
                    background: rgba(0, 0, 0, 0.8);
                    color: white;
                    padding: 10px;
                    border-radius: 4px;
                    font-size: 0.85em;
                    max-width: 300px;
                    z-index: 1000;
                    display: none;
                    pointer-events: none;
                }}
                
                /* Modal styles */
                .modal {{
                    display: none;
                    position: fixed;
                    z-index: 2000;
                    left: 0;
                    top: 0;
                    width: 100%;
                    height: 100%;
                    background-color: rgba(0, 0, 0, 0.5);
                }}
                
                .modal-content {{
                    background-color: white;
                    margin: 5% auto;
                    padding: 20px;
                    border-radius: 8px;
                    width: 80%;
                    max-width: 800px;
                    max-height: 80%;
                    overflow-y: auto;
                }}
                
                .modal h2 {{
                    margin-top: 0;
                    color: #333;
                }}
                
                .detail-section {{
                    margin-bottom: 20px;
                    padding: 15px;
                    background: #f8f9fa;
                    border-radius: 6px;
                }}
                
                .detail-section h3 {{
                    margin-top: 0;
                    color: #333;
                }}
                
                .processor-list {{
                    max-height: 400px;
                    overflow-y: auto;
                }}
                
                .processor-item {{
                    margin-bottom: 15px;
                    padding: 10px;
                    background: white;
                    border-radius: 4px;
                    border-left: 3px solid #2196f3;
                }}
                
                .processor-item h4 {{
                    margin: 0 0 8px 0;
                    color: #333;
                }}
                
                .processor-config {{
                    background: #f5f5f5;
                    padding: 10px;
                    border-radius: 4px;
                    overflow-x: auto;
                }}
                
                .processor-config pre {{
                    margin: 0;
                    font-size: 0.8em;
                    white-space: pre-wrap;
                }}
                
                .modal-actions {{
                    margin-top: 20px;
                    text-align: right;
                }}
                
                .close-btn {{
                    padding: 10px 20px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: #f44336;
                    color: white;
                    cursor: pointer;
                }}
                
                .close-btn:hover {{
                    background: #d32f2f;
                }}
                
                /* Expandable text styles */
                .expandable-text {{
                    color: #2196f3;
                    cursor: pointer;
                    text-decoration: underline;
                    font-weight: 500;
                    transition: color 0.2s ease;
                }}
                
                .expandable-text:hover {{
                    color: #1976d2;
                    background-color: rgba(33, 150, 243, 0.1);
                    padding: 2px 4px;
                    border-radius: 3px;
                }}
                
                .expandable-text.expanded {{
                    color: #f57c00;
                    text-decoration: none;
                }}
                
                .collapse-indicator {{
                    font-size: 0.8em;
                    color: #666;
                    font-style: italic;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="level-badge">{current_level['title']}</div>
                    <h2>Elasticsearch Pipeline Infrastructure Analysis</h2>
                    <p>{current_level['description']}</p>
                </div>
                
                <div class="main-content">
                    <div id="network" class="network-container"></div>
                    <div id="sidebar" class="sidebar">
                        <div class="sidebar-content">
                            <h3>📋 Node Information</h3>
                            <p>Click on a node to see detailed information</p>
                            <div class="help-text">
                                <h4>💡 Interaction Guide:</h4>
                                <ul>
                                    <li><strong>Hover:</strong> Quick info tooltip</li>
                                    <li><strong>Click:</strong> Select and highlight connections</li>
                                    <li><strong>Double-click:</strong> Detailed information modal</li>
                                    <li><strong>Drag:</strong> Reposition nodes</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Tooltip -->
                <div id="tooltip" class="tooltip"></div>
                
                <!-- Detail Modal -->
                <div id="detailModal" class="modal">
                    <div class="modal-content">
                        <div id="modalContent"></div>
                    </div>
                </div>
                
                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="network.moveTo({{scale: network.getScale() * 1.2}})">🔍+ Zoom In</button>
                    <button class="zoom-btn" onclick="network.moveTo({{scale: network.getScale() * 0.8}})">🔍- Zoom Out</button>
                    <button class="zoom-btn" onclick="network.fit()">🔄 Reset</button>
                </div>
                
                <div class="export-controls">
                    <button class="export-btn" onclick="exportAsPNG()">📷 Export PNG</button>
                    <button class="export-btn" onclick="exportAsSVG()">📄 Export SVG</button>
                    <button class="export-btn flow-btn" onclick="toggleDataFlowAnimation()">▶️ Show Data Flow</button>
                </div>
                
                <div class="legend">
                    <div class="legend-section">
                        <h3>Node Types</h3>"""
        
        # Add legend items for current level
        for node_type, color, description in current_level['legend_items']:
            html_content += f"""
                        <div class="legend-item">
                            <span class="legend-color" style="background-color: {color};"></span>
                            <span>{description}</span>
                        </div>"""
        
        html_content += """
                    </div>
                    <div class="legend-section">
                        <h3>Relationship Types</h3>
                        <div class="relationship-types">
                            <span class="relationship-type">default → Default Pipeline</span>
                            <span class="relationship-type">final → Final Pipeline</span>
                            <span class="relationship-type">calls → Pipeline Reference</span>
                            <span class="relationship-type">enriches with → Enrichment Process</span>
                            <span class="relationship-type">uses → Resource Usage</span>
                            <span class="relationship-type">source → Source Index</span>
                        </div>
                    </div>
                </div>"""
        
        # Add processor phase information for pipeline detail and processor detail levels
        if visualization_level in ['pipeline_detail', 'processor_detail']:
            html_content += f"""
                <div class="phase-info">
                    <h3>📋 Processing Phases Explained</h3>
                    <p>Processors are automatically categorized into logical phases based on their function:</p>"""
            
            for phase_id, phase_info in self.processor_phases.items():
                processors_text = ", ".join(phase_info['processors'][:5])
                additional_processors = phase_info['processors'][5:]
                
                if len(phase_info['processors']) > 5:
                    additional_text = ", ".join(additional_processors)
                    processors_text += f""" <span class="expandable-text" 
                        data-full-text="{additional_text}" 
                        data-count="{len(additional_processors)}"
                        onclick="toggleExpandableText(this)"
                        title="Click to expand: {additional_text}">
                        (+ {len(additional_processors)} more)
                    </span>"""
                
                html_content += f"""
                    <div class="phase-category">
                        <strong>{phase_info['name']}:</strong> {processors_text}
                    </div>"""
            
            html_content += """
                </div>"""
        
        html_content += """
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
    y = (screen_height/2) - (900/2)
    root.geometry(f'1200x900+{int(x)}+{int(y)}')
    
    # Make window resizable
    root.resizable(True, True)
    
    # Configure grid weights
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
