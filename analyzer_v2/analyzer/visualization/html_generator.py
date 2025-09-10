import json
import webbrowser
import tempfile
import re
import os
from collections import defaultdict, Counter
from ..config.settings import PROCESSOR_PHASES

class HTMLGenerator:
    def __init__(self, infrastructure_data, processor_analyzer):
        self.infrastructure_data = infrastructure_data
        self.processor_analyzer = processor_analyzer

    def _generate_interactive_data(self, selected_items, analysis_type, visualization_level):
        """Generate data structure for interactive visualization."""
        nodes = []
        edges = []
        visited = set()

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
                    'font': {'color': '#0277bd'},
                    'size': 20
                })
            elif node_type == 'pipeline':
                node_data.update({
                    'color': {'background': '#f3e5f5', 'border': '#7b1fa2'},
                    'shape': 'box',
                    'font': {'color': '#7b1fa2'},
                    'size': 18
                })
            elif node_type == 'enrich':
                node_data.update({
                    'color': {'background': '#e8f5e8', 'border': '#388e3c'},
                    'shape': 'ellipse',
                    'font': {'color': '#388e3c'},
                    'size': 16
                })
            elif node_type == 'phase':
                node_data.update({
                    'color': {'background': '#fff3e0', 'border': '#f57c00'},
                    'shape': 'diamond',
                    'font': {'color': '#f57c00'},
                    'size': 14
                })
            elif node_type == 'processor_group':
                node_data.update({
                    'color': {'background': '#fce4ec', 'border': '#c2185b'},
                    'shape': 'dot',
                    'font': {'color': '#c2185b'},
                    'size': 10
                })
            elif node_type == 'index_template':
                node_data.update({
                    'color': {'background': '#e8eaf6', 'border': '#3f51b5'},
                    'shape': 'hexagon',
                    'font': {'color': '#3f51b5'},
                    'size': 15
                })
            elif node_type == 'component_template':
                node_data.update({
                    'color': {'background': '#f1f8e9', 'border': '#689f38'},
                    'shape': 'triangle',
                    'font': {'color': '#689f38'},
                    'size': 12
                })
            elif node_type == 'transform':
                node_data.update({
                    'color': {'background': '#e0f7fa', 'border': '#00acc1'},
                    'shape': 'hexagon',
                    'font': {'color': '#00acc1'},
                    'size': 18
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
            
            if edge_type == 'calls':
                edge_data.update({
                    'color': {'color': '#ff9800'}, 'arrows': {'to': {'enabled': True}}, 'dashes': False
                })
            elif edge_type == 'enriches':
                edge_data.update({
                    'color': {'color': '#4caf50'}, 'arrows': {'to': {'enabled': True}}, 'dashes': [5, 5]
                })
            elif edge_type == 'dest_pipeline':
                edge_data.update({
                    'color': {'color': '#9c27b0'}, 'arrows': {'to': {'enabled': True}}, 'dashes': [2, 4]
                })
            elif edge_type == 'index_template_match':
                edge_data.update({
                    'color': {'color': '#3f51b5'}, 'arrows': {'to': {'enabled': True}}, 'dashes': [5, 3]
                })
            else:
                edge_data.update({
                    'color': {'color': '#2196f3'}, 'arrows': {'to': {'enabled': True}}, 'dashes': False
                })
            
            edges.append(edge_data)

        def add_pipeline_phases_interactive(pipeline_name, pipeline_node_id):
            """Add phase nodes for pipeline detail level in interactive visualization."""
            if visualization_level != 'pipeline_detail':
                return pipeline_node_id
                
            phases = self.processor_analyzer.get_pipeline_phases(pipeline_name)
            
            if not phases:
                pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                actual_processors = [next(iter(p.keys())) for p in pipeline_info.get('processors', [])]
                if actual_processors:
                    phases = {
                        'processing': [{'type': proc_type, 'config': {}, 'details': []} for proc_type in actual_processors]
                    }
            
            if not phases:
                return pipeline_node_id
                
            stats, total_processors = self.processor_analyzer.get_phase_statistics(phases)
            
            prev_phase_id = pipeline_node_id
            last_phase_id = pipeline_node_id
            
            phase_order = ['input_parsing', 'transformation', 'enrichment', 'processing', 'formatting', 'orchestration']
            ordered_phases = [(p, phases[p]) for p in phase_order if p in phases]
            
            for phase_id, processors in ordered_phases:
                phase_info = PROCESSOR_PHASES[phase_id]
                phase_node_id = f"{pipeline_node_id}_{phase_id}"
                
                stat = stats.get(phase_id, {'count': 0, 'percentage': 0, 'top_processor': 'none'})
                phase_label = f"{phase_info['name']}\n({stat['count']} processors, {stat['percentage']:.1f}%)\nTop: {stat['top_processor']}"
                
                phase_metadata = {
                    'processor_count': stat['count'],
                    'percentage': stat['percentage'],
                    'top_processor': stat['top_processor'],
                    'phase_name': phase_info['name']
                }
                
                phase_detailed_info = {
                    'processors': processors,
                    'processor_types': stat.get('processor_types', {}),
                    'phase_description': f"This phase handles {phase_info['name'].lower()} operations"
                }
                
                add_node_data(phase_node_id, phase_label, 'phase', phase_metadata, phase_detailed_info)
                
                if prev_phase_id == pipeline_node_id:
                    add_edge_data(pipeline_node_id, phase_node_id, 'processes')
                else:
                    add_edge_data(prev_phase_id, phase_node_id, 'then')
                
                prev_phase_id = phase_node_id
                last_phase_id = phase_node_id
                
                if phase_id == 'enrichment':
                    pipeline_info = self.infrastructure_data['pipelines'].get(pipeline_name, {})
                    for policy in pipeline_info.get('uses_enrich', set()):
                        policy_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', policy)}_enrich"
                        add_edge_data(phase_node_id, policy_id, 'uses')
            
            return last_phase_id

        def add_processor_groups_interactive(pipeline_name, pipeline_node_id):
            """Add processor group nodes for processor detail level in interactive visualization."""
            if visualization_level != 'processor_detail':
                return pipeline_node_id
                
            phases = self.processor_analyzer.get_pipeline_phases(pipeline_name)
            
            if not phases:
                return pipeline_node_id
            
            phase_order = ['input_parsing', 'transformation', 'enrichment', 'processing', 'formatting', 'orchestration']
            ordered_phases = [(p, phases[p]) for p in phase_order if p in phases]
            
            prev_element_id = pipeline_node_id
            
            for phase_id, processors in ordered_phases:
                phase_info = PROCESSOR_PHASES[phase_id]
                phase_node_id = f"{pipeline_node_id}_{phase_id}"
                
                processor_groups = defaultdict(list)
                for processor in processors:
                    processor_groups[processor['type']].append(processor)
                
                if len(processor_groups) == 1:
                    proc_type = list(processor_groups.keys())[0]
                    group_node_id = f"{phase_node_id}_{proc_type}"
                    
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
                
                processor_details = []
                for processor in pipeline_info.get('processors', []):
                    proc_type = next(iter(p for p in processor if p not in ['if', 'ignore_failure', 'on_failure', 'tag']))
                    proc_config = processor[proc_type]
                    processor_details.append({'type': proc_type, 'config': proc_config})
                
                processor_types = Counter(p['type'] for p in processor_details)
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
                
                add_node_data(node_id, item, 'pipeline', metadata, detailed_info)
                
                last_node_id = node_id
                if visualization_level == 'pipeline_detail':
                    last_node_id = add_pipeline_phases_interactive(item, node_id)
                elif visualization_level == 'processor_detail':
                    last_node_id = add_processor_groups_interactive(item, node_id)

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
                pipeline_chains = index_info.get('pipeline_chains', [])
                
                metadata = {
                    'pipeline_chain_length': len(pipeline_chains),
                    'default_pipeline': index_info.get('default_pipeline'),
                    'final_pipeline': index_info.get('final_pipeline')
                }
                
                detailed_info = {
                    'pipeline_chains': pipeline_chains,
                    'settings': {
                        'default_pipeline': index_info.get('default_pipeline'),
                        'final_pipeline': index_info.get('final_pipeline')
                    },
                    'full_settings': index_info.get('full_settings', {}),
                    'mappings': index_info.get('mappings', {}),
                    'stats': index_info.get('stats', {})
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
                
                metadata = {
                    'source_count': len(policy_info.get('source_indices', [])),
                    'used_by_count': len(policy_info.get('used_by_pipelines', set())),
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

            elif component_type == 'index_template':
                template_info = self.infrastructure_data['index_templates'].get(item, {})
                
                metadata = {
                    'pattern_count': len(template_info.get('index_patterns', [])),
                    'component_count': len(template_info.get('composed_of', [])),
                    'priority': template_info.get('priority', 0)
                }
                
                detailed_info = {
                    'index_patterns': template_info.get('index_patterns', []),
                    'composed_of': template_info.get('composed_of', []),
                    'priority': template_info.get('priority', 0),
                    'template': template_info.get('template', {}),
                    'data_stream': template_info.get('data_stream', {})
                }
                
                add_node_data(node_id, item, 'index_template', metadata, detailed_info)
                
                for component_template in template_info.get('composed_of', []):
                    component_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', component_template)}_component_template"
                    add_edge_data(node_id, component_id, 'uses')
                    process_relationships(component_template, 'component_template')
                
                template_settings = template_info.get('template', {}).get('settings', {})
                if template_settings.get('index.default_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', template_settings['index.default_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'default pipeline')
                    process_relationships(template_settings['index.default_pipeline'], 'pipeline')
                
                if template_settings.get('index.final_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', template_settings['index.final_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'final pipeline')
                    process_relationships(template_settings['index.final_pipeline'], 'pipeline')
            
            elif component_type == 'component_template':
                template_info = self.infrastructure_data['component_templates'].get(item, {})
                
                metadata = {
                    'used_by_count': len(template_info.get('used_by_index_templates', set())),
                    'version': template_info.get('version')
                }
                
                detailed_info = {
                    'template': template_info.get('template', {}),
                    'version': template_info.get('version'),
                    'used_by_index_templates': list(template_info.get('used_by_index_templates', set()))
                }
                
                add_node_data(node_id, item, 'component_template', metadata, detailed_info)

                template_settings = template_info.get('template', {}).get('settings', {})
                if template_settings.get('index.default_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', template_settings['index.default_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'default pipeline')
                    process_relationships(template_settings['index.default_pipeline'], 'pipeline')

                if template_settings.get('index.final_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', template_settings['index.final_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'final pipeline')
                    process_relationships(template_settings['index.final_pipeline'], 'pipeline')

            elif component_type == 'transform':
                transform_info = self.infrastructure_data['transforms'].get(item, {})
                stats = transform_info.get('stats', {})
                runtime_stats = transform_info.get('runtime_stats', {})
                all_stats = {**stats, **runtime_stats}

                metadata = {
                    'source_count': len(transform_info.get('source_indices', set())),
                    'enabled': transform_info.get('enabled', False),
                    'dest_index': transform_info.get('dest_index'),
                    'processed_docs': all_stats.get('documents_processed', 0),
                    'processing_time': all_stats.get('processing_time_in_ms', 0),
                    'frequency': transform_info.get('frequency'),
                    'state': all_stats.get('state'),
                    'health': all_stats.get('health')
                }

                detailed_info = {
                    'source_index': transform_info.get('source_index'),
                    'dest_index': transform_info.get('dest_index'),
                    'dest_pipeline': transform_info.get('dest_pipeline'),
                    'aggregation_config': transform_info.get('aggregation_config', {}),
                    'group_by_config': transform_info.get('group_by_config', {}),
                    'frequency': transform_info.get('frequency'),
                    'sync_config': transform_info.get('sync_config', {}),
                    'retention_policy': transform_info.get('retention_policy', {}),
                    'enabled': transform_info.get('enabled', False),
                    'stats': stats,
                    'runtime_stats': runtime_stats,
                    'settings': transform_info.get('settings', {}),
                    'source_indices': list(transform_info.get('source_indices', set()))
                }

                add_node_data(node_id, item, 'transform', metadata, detailed_info)

                for source_index in transform_info.get('source_indices', set()):
                    index_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', source_index)}_index"
                    add_edge_data(node_id, index_id, 'sources from')
                    process_relationships(source_index, 'index')

                if transform_info.get('dest_index'):
                    dest_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', transform_info['dest_index'])}_index"
                    add_edge_data(node_id, dest_id, 'creates')
                    process_relationships(transform_info['dest_index'], 'index')

                if transform_info.get('dest_pipeline'):
                    pipeline_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', transform_info['dest_pipeline'])}_pipeline"
                    add_edge_data(node_id, pipeline_id, 'dest pipeline', 'dest_pipeline')
                    process_relationships(transform_info['dest_pipeline'], 'pipeline')

                if transform_info.get('dest_index'):
                    dest_index = transform_info['dest_index']
                    for template_name, template_info in self.infrastructure_data['index_templates'].items():
                        for pattern in template_info.get('index_patterns', []):
                            escaped_pattern = re.escape(pattern).replace('\\*', '.*')
                            if re.match(f"^{escaped_pattern}$", dest_index):
                                template_id = f"{re.sub(r'[^a-zA-Z0-9]', '_', template_name)}_index_template"
                                add_edge_data(template_id, node_id, 'applies to transform', 'index_template_match')
                                process_relationships(template_name, 'index_template')
                                break
        
        for item in selected_items:
            process_relationships(item, analysis_type)
        
        return {'nodes': nodes, 'edges': edges}

    def generate(self, selected_items, analysis_type, visualization_level, root):
        graph_data = self._generate_interactive_data(selected_items, analysis_type, visualization_level)
        
        level_info = {
            "overview": {"title": "📊 Overview Level", "description": "High-level relationships", "legend_items": [("index", "#e1f5fe", "Index"), ("pipeline", "#f3e5f5", "Pipeline"), ("enrich", "#e8f5e8", "Enrichment Policy"), ("transform", "#e0f7fa", "Transform")]},
            "pipeline_detail": {"title": "🔧 Pipeline Detail Level", "description": "Logical processing phases", "legend_items": [("index", "#e1f5fe", "Index"), ("pipeline", "#f3e5f5", "Pipeline"), ("enrich", "#e8f5e8", "Enrichment Policy"), ("phase", "#fff3e0", "Processing Phase"), ("transform", "#e0f7fa", "Transform")]},
            "processor_detail": {"title": "🔬 Processor Detail Level", "description": "Detailed processor groups", "legend_items": [("index", "#e1f5fe", "Index"), ("pipeline", "#f3e5f5", "Pipeline"), ("enrich", "#e8f5e8", "Enrichment Policy"), ("phase", "#fff3e0", "Processing Phase"), ("processor_group", "#fce4ec", "Processor Group"), ("transform", "#e0f7fa", "Transform")]}
        }
        
        current_level = level_info[visualization_level]
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Elasticsearch Pipeline Relationships - {current_level['title']}</title>
            <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/FileSaver.js/2.0.5/FileSaver.min.js"></script>
            <script src="https://unpkg.com/three@0.150.1/build/three.min.js"></script>
            <script src="https://unpkg.com/3d-force-graph@1.73.3/dist/3d-force-graph.min.js"></script>
            <script>
                const graphData = {json.dumps(graph_data, indent=2)};
                let network;
                let graph3D;
                let is3DMode = false;
                let selectedNode = null;
                let animationRunning = false;
                let animationInterval = null;
                let particles = [];
                let _3dClickTimeout = null;
                let lastMousePos = {{ x: 0, y: 0 }};
                let linkDistance = 120;
                let chargeStrength = -120;

                document.addEventListener('mousemove', (e) => {{ lastMousePos = {{ x: e.clientX, y: e.clientY }}; }});
                
                function initNetwork() {{
                    const container = document.getElementById('network');
                    const options = {{
                        nodes: {{ borderWidth: 2, shadow: true, font: {{ size: 14, face: 'Arial' }}, margin: 15, widthConstraint: {{ minimum: 120, maximum: 220 }} }},
                        edges: {{ width: 2, shadow: true, smooth: {{ type: 'continuous' }}, font: {{ size: 12, align: 'middle' }}, length: 200 }},
                        physics: {{ enabled: true, stabilization: {{ enabled: true, iterations: 300, updateInterval: 25 }}, barnesHut: {{ gravitationalConstant: -2000, centralGravity: 0.05, springLength: 300, springConstant: 0.04, damping: 0.4, avoidOverlap: 0.3 }}, solver: 'barnesHut' }},
                        interaction: {{ hover: true, tooltipDelay: 300, dragNodes: true, dragView: true, zoomView: true }},
                        layout: {{ improvedLayout: true, randomSeed: 42 }}
                    }};
                    network = new vis.Network(container, graphData, options);
                    network.on('stabilizationIterationsDone', () => network.setOptions({{ physics: false }}));
                    network.on('hoverNode', (e) => showTooltip(e.pointer.DOM, graphData.nodes.find(n => n.id === e.node)));
                    network.on('blurNode', () => hideTooltip());
                    network.on('click', onClick);
                    network.on('doubleClick', onDoubleClick);
                }}

                let clickTimeout = null;
                function onClick(event) {{
                    if (clickTimeout) {{ clearTimeout(clickTimeout); clickTimeout = null; return; }}
                    clickTimeout = setTimeout(() => {{
                        if (event.nodes.length > 0) {{
                            const node = graphData.nodes.find(n => n.id === event.nodes[0]);
                            if (node) selectNode(node);
                        }} else {{ clearSelection(); }}
                        clickTimeout = null;
                    }}, 250);
                }}

                function onDoubleClick(event) {{
                    if (clickTimeout) {{ clearTimeout(clickTimeout); clickTimeout = null; }}
                    if (event.nodes.length > 0) {{
                        const node = graphData.nodes.find(n => n.id === event.nodes[0]);
                        if (node) showDetailModal(node);
                    }}
                }}
                
                function showTooltip(position, node) {{
                    if (!node) return;
                    const tooltip = document.getElementById('tooltip');
                    const metadata = node.metadata || {{}};
                    let content = `<strong>${{node.label}}</strong><br/><em>Type: ${{node.type}}</em><br/><br/>`;
                    if (node.type === 'pipeline') content += `Processors: ${{metadata.processor_count || 0}}<br/>Top: ${{metadata.top_processor || 'none'}}<br/>`;
                    else if (node.type === 'index') content += `Chain: ${{metadata.pipeline_chain_length || 0}} steps<br/>`;
                    else if (node.type === 'enrich') content += `Sources: ${{metadata.source_count || 0}}<br/>Used by: ${{metadata.used_by_count || 0}}<br/>`;
                    else if (node.type === 'transform') content += `Status: ${{metadata.enabled ? '✅' : '❌'}}<br/>Docs: ${{metadata.processed_docs || 0}}<br/>`;
                    content += `<br/><small>💡 Click to select, double-click for details</small>`;
                    tooltip.innerHTML = content;
                    tooltip.style.left = (position.x + 10) + 'px';
                    tooltip.style.top = (position.y - 10) + 'px';
                    tooltip.style.display = 'block';
                }}
                
                function hideTooltip() {{ document.getElementById('tooltip').style.display = 'none'; }}
                
                function selectNode(node) {{
                    selectedNode = node;
                    updateSidebar(node);
                    network.selectNodes([node.id]);
                    network.selectEdges(network.getConnectedEdges(node.id));
                }}
                
                function clearSelection() {{
                    selectedNode = null;
                    updateSidebar(null);
                    network.unselectAll();
                }}
                
                function updateSidebar(node) {{
                    const sidebar = document.getElementById('sidebar');
                    if (!node) {{
                        sidebar.innerHTML = `<div class="sidebar-content"><h3>📋 Node Information</h3><p>Click on a node to see details</p></div>`;
                        return;
                    }}

                    const metadata = node.metadata || {{}};
                    const detailedInfo = node.detailed_info || {{}};
                    
                    const header = `<h3>${{node.label}}</h3><div class="node-type-badge node-type-${{node.type}}">${{node.type.toUpperCase()}}</div>`;
                    
                    let sections = [];

                    const formatList = (title, items, listType = 'ul') => {{
                        if (items && items.length > 0) {{
                            return `<div class="info-section"><h4>${{title}}</h4><${{listType}}>${{items.map(item => `<li>${{item}}</li>`).join('')}}</${{listType}}></div>`;
                        }}
                        return '';
                    }};

                    const formatStats = (stats) => {{
                        let content = '<div class="info-section"><h4>📊 Stats</h4>';
                        for (const [key, value] of Object.entries(stats)) {{
                            content += `<div>${{key}}: <strong>${{value}}</strong></div>`;
                        }}
                        content += '</div>';
                        return content;
                    }};

                    if (node.type === 'pipeline') {{
                        sections.push(formatStats({{
                            'Processors': metadata.processor_count,
                            'Top Processor': metadata.top_processor,
                            'Description': metadata.description
                        }}));
                        sections.push(formatList('🔗 Calls Pipelines', detailedInfo.calls_pipelines));
                        sections.push(formatList('📈 Uses Enrich Policies', detailedInfo.uses_enrich));
                        sections.push(formatList('🤙 Called By', detailedInfo.called_by));
                    }} else if (node.type === 'index') {{
                        sections.push(formatStats({{
                            'Default Pipeline': metadata.default_pipeline || 'none',
                            'Final Pipeline': metadata.final_pipeline || 'none'
                        }}));
                        sections.push(formatList('⛓️ Pipeline Chain', detailedInfo.pipeline_chains, 'ol'));
                    }} else if (node.type === 'enrich') {{
                        sections.push(formatStats({{
                            'Match Field': metadata.match_field,
                            'Sources': metadata.source_count,
                            'Used By': metadata.used_by_count
                        }}));
                        sections.push(formatList('📦 Source Indices', detailedInfo.source_indices));
                        sections.push(formatList('🤙 Used By Pipelines', detailedInfo.used_by_pipelines));
                    }} else if (node.type === 'transform') {{
                        sections.push(formatStats({{
                            'Status': metadata.enabled ? '✅ Enabled' : '❌ Disabled',
                            'State': metadata.state,
                            'Health': metadata.health,
                            'Processed Docs': metadata.processed_docs,
                            'Frequency': metadata.frequency
                        }}));
                        sections.push(formatList('📦 Source Indices', detailedInfo.source_indices));
                        if(detailedInfo.dest_index) sections.push(formatList('🎯 Destination Index', [detailedInfo.dest_index]));
                        if(detailedInfo.dest_pipeline) sections.push(formatList('🔩 Destination Pipeline', [detailedInfo.dest_pipeline]));
                    }} else if (node.type === 'index_template') {{
                        sections.push(formatStats({{'Priority': metadata.priority, 'Components': metadata.component_count}}));
                        sections.push(formatList('🧩 Index Patterns', detailedInfo.index_patterns));
                        sections.push(formatList('🧱 Composed Of', detailedInfo.composed_of));
                    }} else if (node.type === 'component_template') {{
                        sections.push(formatStats({{'Version': metadata.version, 'Used By': metadata.used_by_count}}));
                        sections.push(formatList('🏗️ Used By Templates', detailedInfo.used_by_index_templates));
                    }} else if (node.type === 'phase') {{
                         sections.push(formatStats({{
                            'Phase': metadata.phase_name,
                            'Processors': metadata.processor_count,
                            'Coverage': `${{metadata.percentage.toFixed(1)}}%`,
                            'Top Processor': metadata.top_processor,
                        }}));
                        const procTypes = Object.entries(detailedInfo.processor_types || {{}}).map(([key, val]) => `<li>${{key}}: ${{val}}</li>`).join('');
                        if (procTypes) sections.push(`<div class="info-section"><h4>⚙️ Processor Types</h4><ul>${{procTypes}}</ul></div>`);
                    }} else if (node.type === 'processor_group') {{
                        sections.push(formatStats({{
                            'Processor': metadata.processor_type,
                            'Phase': metadata.phase_name,
                            'Count': metadata.count
                        }}));
                        sections.push(formatList('🔧 Sample Config', metadata.sample_config));
                    }}

                    const buttons = `<div class="action-buttons"><button onclick="showDetailModal(selectedNode)">🔍 Details</button><button onclick="focusOnNode('${{node.id}}')">🎯 Focus</button></div>`;
                    
                    sidebar.innerHTML = `<div class="sidebar-content">${{header}}${{sections.join('')}}${{buttons}}</div>`;
                }}
                
                function showDetailModal(node) {{
                    const modal = document.getElementById('detailModal');
                    const modalContent = document.getElementById('modalContent');
                    const detailedInfo = node.detailed_info || {{}};
                    let content = `<h2>${{node.label}}</h2>`;
                    if (node.type === 'pipeline') {{
                        content += `<h3>🔧 Processors (${{detailedInfo.processors.length}})</h3><div class="processor-list">${{detailedInfo.processors.map((p, i) => `<div class="processor-item"><h4>${{i+1}}. ${{p.type}}</h4><pre>${{JSON.stringify(p.config, null, 2)}}</pre></div>`).join('')}}</div>`;
                    }} else if (node.type === 'index') {{
                        content += `<h3>⚙️ Settings</h3><pre>${{JSON.stringify(detailedInfo.full_settings, null, 2)}}</pre>`;
                    }} else if (node.type === 'transform') {{
                        content += `<h3>⚙️ Config</h3><pre>${{JSON.stringify(detailedInfo, null, 2)}}</pre>`;
                    }}
                    modalContent.innerHTML = content;
                    modal.style.display = 'block';
                }}
                
                function closeModal() {{ document.getElementById('detailModal').style.display = 'none'; }}
                
                function focusOnNode(nodeId) {{ network.focus(nodeId, {{ scale: 1.5, animation: true }}); }}

                function exportAsPNG() {{
                    // Create a temporary canvas to draw on
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    
                    // Get the network canvas
                    const networkCanvas = network.canvas.frame.canvas;
                    canvas.width = networkCanvas.width;
                    canvas.height = networkCanvas.height;
                    
                    // Draw a white background
                    ctx.fillStyle = '#FFFFFF';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    
                    // Draw the network on top
                    ctx.drawImage(networkCanvas, 0, 0);
                    
                    // Trigger download
                    canvas.toBlob(function(blob) {{
                        saveAs(blob, 'pipeline_diagram.png');
                    }});
                }}

                function exportAsSVG() {{
                    alert('SVG export is not fully supported and may be incomplete. Use PNG for a more accurate representation.');
                    const svgData = network.canvas.getContext().getSvg();
                    const blob = new Blob([svgData], {{type: 'image/svg+xml'}});
                    saveAs(blob, 'pipeline_diagram.svg');
                }}

                function toggleDataFlowAnimation() {{
                    if (animationRunning) {{
                        stopDataFlowAnimation();
                    }} else {{
                        startDataFlowAnimation();
                    }}
                }}

                function startDataFlowAnimation() {{
                    if (animationRunning) return;
                    animationRunning = true;
                    particles = [];
                    const flowBtn = document.querySelector('.export-btn[onclick="toggleDataFlowAnimation()"]');
                    if(flowBtn) flowBtn.textContent = '⏸️ Stop Data Flow';

                    animationInterval = setInterval(() => {{
                        if (!animationRunning) {{
                            clearInterval(animationInterval);
                            return;
                        }}
                        
                        graphData.edges.forEach(edge => {{
                            if (Math.random() < 0.1) {{ // Spawn particles with a certain probability
                                const fromNode = network.getPositions([edge.from])[edge.from];
                                const toNode = network.getPositions([edge.to])[edge.to];
                                if(fromNode && toNode) {{
                                    particles.push({{
                                        from: fromNode,
                                        to: toNode,
                                        progress: 0,
                                        color: edge.color ? edge.color.color : '#848484'
                                    }});
                                }}
                            }}
                        }});

                        particles.forEach((p, index) => {{
                            p.progress += 0.01;
                            if (p.progress >= 1) {{
                                particles.splice(index, 1);
                            }}
                        }});

                        network.redraw();
                    }}, 50);

                    network.on('afterDrawing', function(ctx) {{
                        particles.forEach(p => {{
                            const pos = {{
                                x: p.from.x + (p.to.x - p.from.x) * p.progress,
                                y: p.from.y + (p.to.y - p.from.y) * p.progress
                            }};
                            ctx.fillStyle = p.color;
                            ctx.beginPath();
                            ctx.arc(pos.x, pos.y, 4, 0, 2 * Math.PI);
                            ctx.fill();
                        }});
                    }});
                }}

                function stopDataFlowAnimation() {{
                    animationRunning = false;
                    clearInterval(animationInterval);
                    const flowBtn = document.querySelector('.export-btn[onclick="toggleDataFlowAnimation()"]');
                    if(flowBtn) flowBtn.textContent = '▶️ Show Data Flow';
                    network.off('afterDrawing'); // Important to remove listener
                    network.redraw();
                }}

                function init3DGraph() {{
                    const container = document.getElementById('graph3d');
                    const mapped = {{
                        nodes: graphData.nodes.map(n => ({{ ...n, name: n.label, color3d: (n.color && n.color.background) || '#999999' }})),
                        links: graphData.edges.map(e => ({{ source: e.from, target: e.to, label: e.label, type: e.type }}))
                    }};

                    graph3D = ForceGraph3D({{ rendererConfig: {{ antialias: true, alpha: false }} }})(container)
                        .graphData(mapped)
                        .nodeId('id')
                        .nodeLabel('label')
                        .nodeVal('size')
                        .nodeColor('color3d')
                        .linkColor(l => l.type === 'calls' ? '#ff9800' : '#2196f3')
                        .backgroundColor('#ffffff')
                        .nodeThreeObject(node => {{
                            // Debug log to confirm node types in the browser console
                            try {{ console.debug('[nodeThreeObject] node:', node.id, 'type:', node.type); }} catch(e){{}}
    
                            const geometry = getNodeGeometry(node.type);
                            try {{ if (geometry && !geometry.boundingSphere) {{ geometry.computeBoundingSphere(); }} }} catch(e){{}}
    
                            // Use a material which shows faceted geometry more clearly on light background
                            const material = new THREE.MeshPhongMaterial({{
                                color: node.color3d || 0x999999,
                                specular: 0x888888,
                                shininess: 40,
                                flatShading: false,
                                side: THREE.FrontSide
                            }});
    
                            const mesh = new THREE.Mesh(geometry, material);
                            mesh.castShadow = true;
                            mesh.receiveShadow = true;
                            const group = new THREE.Group();
                            group.add(mesh);
                            const edges = new THREE.LineSegments(
                                new THREE.EdgesGeometry(geometry, 15),
                                new THREE.LineBasicMaterial({{ color: 0x555555, transparent: true, opacity: 0.6 }})
                            );
                            group.add(edges);
    
                            // add label sprite above node
                            const labelTex = createLabelTexture(node.label, 'black');
                            const spriteMat = new THREE.SpriteMaterial({{ map: labelTex, transparent: true, depthTest: false }});
                            const sprite = new THREE.Sprite(spriteMat);
                            const dims = (labelTex.userData && labelTex.userData.dims) ? labelTex.userData.dims : {{ w: 80, h: 24 }};
                            const scaleFactor = 0.20; // world units per pixel
                            sprite.scale.set(dims.w * scaleFactor, dims.h * scaleFactor, 1);
                            sprite.center.set(0.5, 0); // anchor bottom-center
                            const radius = (geometry && geometry.boundingSphere) ? geometry.boundingSphere.radius : 12;
                            sprite.position.y = radius + 8;
                            sprite.renderOrder = 999;
                            group.add(sprite);
    
                            return group;
                        }})
                        .nodeThreeObjectExtend(false);
                    
                    // Configure forces after graph creation (3D uses d3-force-3d)
                    try {{
                        const linkForce = graph3D.d3Force && graph3D.d3Force('link');
                        if (linkForce && linkForce.distance) linkForce.distance(linkDistance);
                        const chargeForce = graph3D.d3Force && graph3D.d3Force('charge');
                        if (chargeForce && chargeForce.strength) chargeForce.strength(chargeStrength);
                        if (graph3D.numDimensions) graph3D.numDimensions(3);
                    }} catch (e) {{ console.warn('Force config error', e); }}
                    
                    const ambientLight = new THREE.AmbientLight(0xffffff, 0.15);
                    const hemiLight = new THREE.HemisphereLight(0xffffff, 0x888888, 0.6);
                    const directionalLight = new THREE.DirectionalLight(0xffffff, 1.0);
                    directionalLight.position.set(-200, 200, 200);
                    directionalLight.castShadow = true;
                    const directionalLight2 = new THREE.DirectionalLight(0xffffff, 0.6);
                    directionalLight2.position.set(200, 120, -150);
                    directionalLight2.castShadow = true;
                    
                    graph3D.scene().add(ambientLight);
                    graph3D.scene().add(hemiLight);
                    graph3D.scene().add(directionalLight);
                    graph3D.scene().add(directionalLight2);
                    
                    // Set white background multiple ways to ensure it works
                    graph3D.cameraPosition({{ z: 500 }});
                    if (graph3D.renderer) {{
                        const r = graph3D.renderer();
                        r.setClearColor(0xffffff, 1);
                        try {{
                            graph3D.scene().background = new THREE.Color(0xffffff);
                            r.shadowMap.enabled = true;
                            r.shadowMap.type = THREE.PCFSoftShadowMap;
                        }} catch(e) {{}}
                        if (r.domElement) {{
                            r.domElement.style.background = '#ffffff';
                        }}
                    }}
                    
                    // Also set container background
                    container.style.backgroundColor = '#ffffff';
                }}

                function getNodeGeometry(nodeType) {{
                    switch (nodeType) {{
                        case 'pipeline':
                            return new THREE.BoxGeometry(12, 12, 12);
                        case 'index':
                            return new THREE.CylinderGeometry(8, 8, 12, 24);
                        case 'phase':
                            return new THREE.ConeGeometry(9, 14, 6);
                        case 'enrich':
                            return new THREE.SphereGeometry(10, 20, 20);
                        case 'transform':
                            return new THREE.DodecahedronGeometry(10);
                        case 'index_template':
                            return new THREE.OctahedronGeometry(10);
                        case 'component_template':
                            return new THREE.TetrahedronGeometry(10);
                        case 'processor_group':
                            return new THREE.TorusGeometry(8, 2, 8, 16);
                        default:
                            return new THREE.SphereGeometry(8, 16, 16);
                    }}
                }}

                function createLabelTexture(text, color) {{
                    const dpr = window.devicePixelRatio || 1;
                    const fontSize = 22;
                    const paddingX = 10, paddingY = 6;
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    
                    // Measure with CSS pixels
                    ctx.font = `bold ${{fontSize}}px Arial`;
                    const textWidth = ctx.measureText(text).width;
                    const width = Math.ceil(textWidth + paddingX * 2);
                    const height = Math.ceil(fontSize + paddingY * 2);
                    
                    // Set actual pixel size for HiDPI
                    canvas.width = Math.ceil(width * dpr);
                    canvas.height = Math.ceil(height * dpr);
                    ctx.scale(dpr, dpr);
                    
                    // Background pill
                    const r = 4;
                    ctx.fillStyle = 'rgba(255,255,255,0.95)';
                    ctx.beginPath();
                    ctx.moveTo(r, 0);
                    ctx.arcTo(width, 0, width, height, r);
                    ctx.arcTo(width, height, 0, height, r);
                    ctx.arcTo(0, height, 0, 0, r);
                    ctx.arcTo(0, 0, width, 0, r);
                    ctx.closePath();
                    ctx.fill();

                    // Text
                    ctx.font = `bold ${{fontSize}}px Arial`;
                    ctx.fillStyle = color || 'black';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(text, width / 2, height / 2);
                    
                    // Texture
                    const texture = new THREE.CanvasTexture(canvas);
                    texture.minFilter = THREE.LinearFilter;
                    texture.magFilter = THREE.LinearFilter;
                    texture.needsUpdate = true;
                    texture.userData = texture.userData || {{}};
                    texture.userData.dims = {{ w: width, h: height }}; // store CSS pixel dims for scaling
                    return texture;
                }}

                function toggle3DMode() {{
                    is3DMode = !is3DMode;
                    document.getElementById('network').style.display = is3DMode ? 'none' : 'block';
                    document.getElementById('graph3d').style.display = is3DMode ? 'block' : 'none';
                    document.getElementById('toggle3dBtn').textContent = `🧭 3D Mode: ${{is3DMode ? 'On' : 'Off'}}`;
                    if (is3DMode && !graph3D) init3DGraph();
                }}
                
                window.addEventListener('load', () => initNetwork());
            </script>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 10px; }}
                .container {{ display: flex; height: calc(100vh - 20px); gap: 10px; }}
                .network-container {{ flex: 1; border: 1px solid #ddd; border-radius: 6px; background: white; }}
                #network, #graph3d {{ height: 100%; width: 100%; background-color: #ffffff !important; }}
                #graph3d canvas {{ background-color: #ffffff !important; }}
                .sidebar {{ width: 300px; border: 1px solid #ddd; border-radius: 6px; background: #f8f9fa; overflow-y: auto; }}
                .sidebar-content {{ padding: 15px; }}
                .node-type-badge {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; margin-bottom: 10px; }}
                .node-type-index {{ background: #e1f5fe; color: #0277bd; }}
                .node-type-pipeline {{ background: #f3e5f5; color: #7b1fa2; }}
                .node-type-enrich {{ background: #e8f5e8; color: #388e3c; }}
                .node-type-transform {{ background: #e0f7fa; color: #00acc1; }}
                .node-type-phase {{ background: #fff3e0; color: #f57c00; }}
                .node-type-processor_group {{ background: #fce4ec; color: #c2185b; }}
                .info-section {{ margin-bottom: 15px; padding: 10px; background: white; border-radius: 4px; border-left: 3px solid #2196f3; }}
                .tooltip {{ position: absolute; background: rgba(0,0,0,0.8); color: white; padding: 10px; border-radius: 4px; font-size: 0.85em; z-index: 1000; display: none; pointer-events: none; }}
                .modal {{ display: none; position: fixed; z-index: 2000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }}
                .modal-content {{ background-color: white; margin: 5% auto; padding: 20px; border-radius: 8px; width: 80%; max-width: 800px; max-height: 80%; overflow-y: auto; }}
                .processor-list {{ max-height: 400px; overflow-y: auto; }}
                .processor-item {{ margin-bottom: 15px; padding: 10px; background: #f5f5f5; border-radius: 4px; }}
                pre {{ white-space: pre-wrap; word-wrap: break-word; background: #eee; padding: 10px; border-radius: 4px; }}
                .zoom-controls, .export-controls, .view-controls {{ position: fixed; background: white; padding: 10px; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); z-index: 1000; display: flex; gap: 8px; }}
                .zoom-controls {{ bottom: 20px; right: 20px; flex-direction: column; }}
                .export-controls {{ bottom: 20px; left: 20px; flex-direction: column; }}
                .view-controls {{ top: 20px; right: 20px; }}
                .zoom-btn, .export-btn, .view-controls button {{ margin: 0; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; background: #f8f8f8; cursor: pointer; font-size: 0.9em; white-space: nowrap; text-align: center; min-width: 120px; }}
                .zoom-btn:hover, .export-btn:hover, .view-controls button:hover {{ background: #e8e8e8; border-color: #999; }}
                .legend {{ position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: rgba(255,255,255,0.9); padding: 10px; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); z-index: 1000; display: flex; gap: 15px; align-items: center; }}
                .legend-item {{ display: flex; align-items: center; gap: 5px; font-size: 0.9em; }}
                .legend-color {{ width: 15px; height: 15px; border-radius: 50%; border: 1px solid #999; }}
                h3, h4 {{ color: #333; }}
                .action-buttons {{ margin-top: 15px; display: flex; gap: 10px; }}
                .action-buttons button {{ flex: 1; padding: 8px; border-radius: 4px; border: 1px solid #ccc; background: #f0f0f0; cursor: pointer; }}
                .action-buttons button:hover {{ background: #e0e0e0; }}
            </style>
        </head>
        <body>
            <div class="zoom-controls">
                <button class="zoom-btn" onclick="network.moveTo({{scale: network.getScale() * 1.2}})">🔍+ Zoom In</button>
                <button class="zoom-btn" onclick="network.moveTo({{scale: network.getScale() * 0.8}})">🔍- Zoom Out</button>
                <button class="zoom-btn" onclick="network.fit()">🔄 Reset</button>
            </div>
            <div class="export-controls">
                <button class="export-btn" onclick="exportAsPNG()">📷 Export PNG</button>
                <button class="export-btn" onclick="exportAsSVG()">📄 Export SVG</button>
                <button class="export-btn" onclick="toggleDataFlowAnimation()">▶️ Show Data Flow</button>
                <button class="export-btn" id="toggle3dBtn" onclick="toggle3DMode()">🧭 3D Mode: Off</button>
            </div>
            <div class="container">
                <div id="network" class="network-container"></div>
                <div id="graph3d" class="network-container" style="display:none"></div>
                <div id="sidebar" class="sidebar"><div class="sidebar-content"><h3>📋 Node Information</h3><p>Click a node for details</p></div></div>
            </div>
            <div id="tooltip" class="tooltip"></div>
            <div id="detailModal" class="modal"><div class="modal-content"><span onclick="closeModal()" style="float:right;cursor:pointer;">&times;</span><div id="modalContent"></div></div></div>
        </body>
        </html>
        """
        
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as f:
                f.write(html_content)
                temp_path = f.name
            
            webbrowser.open(f'file://{os.path.realpath(temp_path)}')
            
            if root:
                root.after(5000, lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)
        except Exception as e:
            print(f"Error generating or opening HTML file: {e}")