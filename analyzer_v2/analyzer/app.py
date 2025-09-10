import tkinter as tk
from tkinter import messagebox
from .ui.main_frame import MainFrame
from .elasticsearch.connection import ConnectionManager
from .elasticsearch.data_fetcher import DataFetcher
from .analysis.relationship_builder import RelationshipBuilder
from .analysis.processor_analyzer import ProcessorAnalyzer
from .visualization.html_generator import HTMLGenerator

class Application:
    def __init__(self, root):
        self.root = root
        self.root.title("Elasticsearch Pipeline Analyzer")
        self.root.geometry("1200x900")
        
        self.main_frame = MainFrame(root)
        
        self.html_generator = None
        self.processor_analyzer = None
        
        self._bind_events()

    def _bind_events(self):
        self.main_frame.credentials_frame.connect_btn.config(command=self.connect_to_es)
        self.main_frame.analysis_frame.analyze_btn.config(command=self.analyze)
        self.main_frame.results_frame.view_btn.config(command=self.view_diagram)

        # Bind radio buttons to update the selection list
        self.main_frame.analysis_frame.index_rb.config(command=self.update_selection_list)
        self.main_frame.analysis_frame.pipeline_rb.config(command=self.update_selection_list)
        self.main_frame.analysis_frame.enrich_rb.config(command=self.update_selection_list)
        self.main_frame.analysis_frame.index_template_rb.config(command=self.update_selection_list)
        self.main_frame.analysis_frame.component_template_rb.config(command=self.update_selection_list)
        self.main_frame.analysis_frame.transform_rb.config(command=self.update_selection_list)

    def connect_to_es(self):
        connection_details = self.main_frame.credentials_frame.get_connection_details()
        try:
            connection_manager = ConnectionManager(connection_details)
            self.es_client = connection_manager.connect()
            
            data_fetcher = DataFetcher(self.es_client)
            self.infrastructure_data = data_fetcher.fetch_all_data()
            
            # Initialize analyzers and generators after data is fetched
            self.processor_analyzer = ProcessorAnalyzer(self.infrastructure_data)
            self.html_generator = HTMLGenerator(self.infrastructure_data, self.processor_analyzer)

            messagebox.showinfo("Success", "Connected to Elasticsearch successfully!")
            self.main_frame.analysis_frame.analyze_btn.config(state=tk.NORMAL)
            self.update_selection_list()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")

    def analyze(self):
        analysis_options = self.main_frame.analysis_frame.get_analysis_options()
        if not analysis_options["selected_items"]:
            messagebox.showwarning("Warning", "Please select at least one item")
            return

        summary = self._generate_analysis_summary(
            analysis_options["selected_items"],
            analysis_options["analysis_type"],
            analysis_options["visualization_level"]
        )
        self.main_frame.results_frame.show_summary(summary)

    def _generate_analysis_summary(self, selected_items, analysis_type, visualization_level):
        summary_lines = []
        if not self.processor_analyzer:
            messagebox.showerror("Error", "Processor analyzer not initialized. Please connect first.")
            return ""

        level_names = {
            'overview': '📊 Overview Level',
            'pipeline_detail': '🔧 Pipeline Detail Level',
            'processor_detail': '🔬 Processor Detail Level'
        }
        
        summary_lines.append(f"=== {level_names[visualization_level]} Analysis ===")
        summary_lines.append(f"Analysis Type: {analysis_type.title()}")
        summary_lines.append(f"Selected Items: {', '.join(selected_items)}")
        summary_lines.append("")

        for item in selected_items:
            summary_lines.append(f"📋 Analysis for: {item}")
            summary_lines.append("-" * 50)
            
            if analysis_type == 'pipeline':
                pipeline_info = self.infrastructure_data['pipelines'].get(item, {})
                processor_count = len(pipeline_info.get('processors', []))
                
                summary_lines.append(f"• Total Processors: {processor_count}")
                
                if visualization_level in ['pipeline_detail', 'processor_detail']:
                    phases = self.processor_analyzer.get_pipeline_phases(item)
                    if phases:
                        summary_lines.append(f"• Processing Phases: {len(phases)}")
                        stats, total = self.processor_analyzer.get_phase_statistics(phases)
                        
                        for phase_id, phase_processors in phases.items():
                            phase_info = self.processor_analyzer.processor_phases[phase_id]
                            stat = stats.get(phase_id, {'count': 0, 'percentage': 0, 'top_processor': 'none'})
                            summary_lines.append(f"  - {phase_info['name']}: {stat['count']} processors ({stat['percentage']:.1f}%)")
                            summary_lines.append(f"    Top processor: {stat['top_processor']}")
                
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

        summary_lines.append("🎯 Next Steps:")
        summary_lines.append("• Click 'View Diagram' to see the interactive visualization")
        
        return "\n".join(summary_lines)

    def view_diagram(self):
        analysis_options = self.main_frame.analysis_frame.get_analysis_options()
        if not analysis_options["selected_items"]:
            messagebox.showwarning("Warning", "Please select at least one item to visualize.")
            return

        if not self.html_generator:
            messagebox.showerror("Error", "HTML generator not initialized. Please connect to Elasticsearch first.")
            return

        self.html_generator.generate(
            analysis_options["selected_items"],
            analysis_options["analysis_type"],
            analysis_options["visualization_level"],
            self.root
        )

    def update_selection_list(self):
        analysis_type = self.main_frame.analysis_frame.analysis_type.get()
        key = analysis_type + 's'
        if analysis_type == 'index':
            key = 'indices'
        elif analysis_type == 'enrich':
            key = 'enrich_policies'

        items = sorted(self.infrastructure_data.get(key, {}).keys())
        self.main_frame.analysis_frame.update_selection_list(items)