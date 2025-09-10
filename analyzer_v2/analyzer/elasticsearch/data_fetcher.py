from tkinter import messagebox
from analyzer.analysis.relationship_builder import RelationshipBuilder

class DataFetcher:
    def __init__(self, es_client):
        self.es_client = es_client
        self.infrastructure_data = {
            'indices': {},
            'pipelines': {},
            'enrich_policies': {},
            'index_templates': {},
            'component_templates': {},
            'transforms': {},
        }

    def fetch_all_data(self):
        """Fetch all required data from Elasticsearch."""
        try:
            self._fetch_indices()
            self._fetch_pipelines()
            self._fetch_enrich_policies()
            self._fetch_index_templates()
            self._fetch_component_templates()
            self._fetch_transforms()
            # After fetching, build the relationships
            builder = RelationshipBuilder(self.infrastructure_data)
            self.infrastructure_data = builder.build_all_relationships()
            return self.infrastructure_data
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch data: {str(e)}")
            raise

    def _fetch_indices(self):
        indices_response = self.es_client.indices.get_settings(flat_settings=True)
        mappings_response = self.es_client.indices.get_mapping()
        stats_response = self.es_client.indices.stats()
        
        for index_name, settings in indices_response.items():
            index_settings = settings.get('settings', {})
            mapping_info = mappings_response.get(index_name, {}).get('mappings', {})
            index_stats = stats_response.get('indices', {}).get(index_name, {})
            
            self.infrastructure_data['indices'][index_name] = {
                'default_pipeline': index_settings.get('index.default_pipeline'),
                'final_pipeline': index_settings.get('index.final_pipeline'),
                'full_settings': index_settings,
                'mappings': mapping_info,
                'stats': index_stats
            }

    def _fetch_pipelines(self):
        pipelines = self.es_client.ingest.get_pipeline()
        for name, info in pipelines.items():
            self.infrastructure_data['pipelines'][name] = {
                'processors': info['processors'],
                'description': info.get('description', ''),
            }

    def _fetch_enrich_policies(self):
        try:
            enrich_response = self.es_client.enrich.get_policy()
            policies = enrich_response.body.get('policies', [])
            for policy in policies:
                name = policy['config']['match']['name']
                self.infrastructure_data['enrich_policies'][name] = {
                    'source_indices': policy['config']['match']['indices'],
                    'match_field': policy['config']['match']['match_field'],
                }
        except Exception as e:
            print(f"Warning: Could not fetch enrich policies: {str(e)}")

    def _fetch_index_templates(self):
        try:
            index_templates_response = self.es_client.indices.get_index_template()
            for template in index_templates_response.get('index_templates', []):
                name = template['name']
                template_config = template['index_template']
                self.infrastructure_data['index_templates'][name] = {
                    'index_patterns': template_config.get('index_patterns', []),
                    'priority': template_config.get('priority', 0),
                    'composed_of': template_config.get('composed_of', []),
                    'template': template_config.get('template', {}),
                    'data_stream': template_config.get('data_stream', {}),
                }
        except Exception as e:
            print(f"Warning: Could not fetch index templates: {str(e)}")

    def _fetch_component_templates(self):
        try:
            component_templates_response = self.es_client.cluster.get_component_template()
            for template in component_templates_response.get('component_templates', []):
                name = template['name']
                template_config = template['component_template']
                self.infrastructure_data['component_templates'][name] = {
                    'template': template_config.get('template', {}),
                    'version': template_config.get('version'),
                }
        except Exception as e:
            print(f"Warning: Could not fetch component templates: {str(e)}")

    def _fetch_transforms(self):
        try:
            transform_response = self.es_client.transform.get_transform()
            transforms_data = transform_response.get('transforms', [])
            stats_response = self.es_client.transform.get_transform_stats(transform_id='*')
            transform_stats = {stat['id']: stat.get('stats', {}) for stat in stats_response.get('transforms', [])}

            for transform_info in transforms_data:
                transform_name = transform_info.get('id', 'unknown')
                self.infrastructure_data['transforms'][transform_name] = {
                    'source_index': transform_info.get('source', {}).get('index'),
                    'dest_index': transform_info.get('dest', {}).get('index'),
                    'dest_pipeline': transform_info.get('dest', {}).get('pipeline'),
                    'aggregation_config': transform_info.get('pivot', {}).get('aggregations', {}),
                    'group_by_config': transform_info.get('pivot', {}).get('group_by', {}),
                    'frequency': transform_info.get('frequency'),
                    'sync_config': transform_info.get('sync', {}),
                    'retention_policy': transform_info.get('retention_policy', {}),
                    'enabled': transform_info.get('enabled', False),
                    'runtime_stats': transform_stats.get(transform_name, {}),
                    'settings': transform_info.get('settings', {}),
                }
        except Exception as e:
            print(f"Warning: Could not fetch transforms: {str(e)}")