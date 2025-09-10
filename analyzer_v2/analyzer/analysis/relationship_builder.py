from collections import defaultdict

class RelationshipBuilder:
    def __init__(self, infrastructure_data):
        self.infrastructure_data = infrastructure_data
        self.infrastructure_data['relationships'] = defaultdict(list)

    def build_all_relationships(self):
        """Builds all relationships in the correct order."""
        self._build_template_relationships()
        self._build_transform_relationships()
        self._build_full_relationship_graph() # This replaces the older, separated methods
        return self.infrastructure_data

    def _build_template_relationships(self):
        """Build relationships between index templates and component templates."""
        for it_name, it_info in self.infrastructure_data.get('index_templates', {}).items():
            composed_of = it_info.get('composed_of', [])
            for ct_name in composed_of:
                if ct_name in self.infrastructure_data.get('component_templates', {}):
                    component = self.infrastructure_data['component_templates'][ct_name]
                    component.setdefault('used_by_index_templates', set()).add(it_name)

    def _build_transform_relationships(self):
        """Build relationships for transform components."""
        for transform_name, transform_info in self.infrastructure_data.get('transforms', {}).items():
            # Handle source indices
            source_index = transform_info.get('source_index')
            if source_index:
                indices = [s.strip() for s in source_index.split(',')] if isinstance(source_index, str) else source_index
                transform_info['source_indices'] = set(indices)

            # Handle destination index
            dest_index = transform_info.get('dest_index')
            if dest_index and dest_index in self.infrastructure_data.get('indices', {}):
                self.infrastructure_data['indices'][dest_index]['created_by_transform'] = transform_name

    def _build_full_relationship_graph(self):
        """
        Builds the comprehensive, top-level relationship graph, including reverse links,
        mimicking the logic from the original monolithic script's `build_relationships` method.
        """
        relationships = self.infrastructure_data['relationships']

        # First pass: Analyze pipeline processors and build pipeline-to-pipeline/enrich relationships
        for pipeline_name, pipeline_info in self.infrastructure_data.get('pipelines', {}).items():
            pipeline_info.setdefault('calls_pipelines', set())
            pipeline_info.setdefault('uses_enrich', set())
            pipeline_info.setdefault('called_by', set())

            for processor in pipeline_info.get('processors', []):
                if 'pipeline' in processor:
                    target_pipeline = processor['pipeline']['name']
                    pipeline_info['calls_pipelines'].add(target_pipeline)
                    if target_pipeline in self.infrastructure_data.get('pipelines', {}):
                        self.infrastructure_data['pipelines'][target_pipeline].setdefault('called_by', set()).add(pipeline_name)
                    relationships[pipeline_name].append(('pipeline', target_pipeline, 'calls'))

                elif 'enrich' in processor:
                    policy_name = processor['enrich']['policy_name']
                    pipeline_info['uses_enrich'].add(policy_name)
                    if policy_name in self.infrastructure_data.get('enrich_policies', {}):
                        self.infrastructure_data['enrich_policies'][policy_name].setdefault('used_by_pipelines', set()).add(pipeline_name)
                    relationships[pipeline_name].append(('enrich', policy_name, 'enriches with'))

        # Second pass: Build complete pipeline chains for each index and their associated relationships
        for index_name, index_info in self.infrastructure_data.get('indices', {}).items():
            index_pipelines = set()

            # Process default pipeline
            if index_info.get('default_pipeline'):
                default_chain = self._get_pipeline_chain(index_info['default_pipeline'])
                index_info.setdefault('pipeline_chains', []).extend(default_chain)
                index_pipelines.update(default_chain)
                relationships[index_name].append(('pipeline', index_info['default_pipeline'], 'default'))

            # Process final pipeline
            if index_info.get('final_pipeline'):
                final_chain = self._get_pipeline_chain(index_info['final_pipeline'])
                index_info.setdefault('pipeline_chains', []).extend(final_chain)
                index_pipelines.update(final_chain)
                relationships[index_name].append(('pipeline', index_info['final_pipeline'], 'final'))
            
            # Add relationships for all pipelines in the chain
            for pipeline_name in index_pipelines:
                if pipeline_name in self.infrastructure_data.get('pipelines', {}):
                    pipeline_info = self.infrastructure_data['pipelines'][pipeline_name]
                    
                    # Add enrichment relationships that stem from this pipeline
                    for policy_name in pipeline_info.get('uses_enrich', set()):
                        relationships[pipeline_name].append(('enrich', policy_name, 'enriches with'))
                        
                        # Add source indices for these enrich policies
                        if policy_name in self.infrastructure_data.get('enrich_policies', {}):
                            policy_info = self.infrastructure_data['enrich_policies'][policy_name]
                            for source_index in policy_info.get('source_indices', []):
                                relationships[policy_name].append(('index', source_index, 'source'))

    def _get_pipeline_chain(self, start_pipeline, visited=None):
        """Recursively get the chain of pipelines, iterating through processors."""
        if visited is None:
            visited = set()
        
        if start_pipeline in visited or start_pipeline not in self.infrastructure_data.get('pipelines', {}):
            return []
        
        visited.add(start_pipeline)
        chain = [start_pipeline]
        
        pipeline_info = self.infrastructure_data['pipelines'][start_pipeline]
        for processor in pipeline_info.get('processors', []):
            if 'pipeline' in processor:
                called_pipeline = processor['pipeline']['name']
                chain.extend(self._get_pipeline_chain(called_pipeline, visited))
        
        return chain