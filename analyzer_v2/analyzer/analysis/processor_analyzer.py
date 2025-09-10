from collections import defaultdict, Counter
from ..config.settings import PROCESSOR_PHASES

class ProcessorAnalyzer:
    def __init__(self, infrastructure_data):
        self.infrastructure_data = infrastructure_data
        self.processor_phases = PROCESSOR_PHASES

    def get_pipeline_phases(self, pipeline_name):
        if pipeline_name not in self.infrastructure_data['pipelines']:
            return {}
        
        pipeline_info = self.infrastructure_data['pipelines'][pipeline_name]
        phases = defaultdict(list)
        
        for processor in pipeline_info['processors']:
            processor_type = self._get_processor_type(processor)
            phase = self._categorize_processor(processor_type)
            phases[phase].append({
                'type': processor_type,
                'config': processor[processor_type],
                'details': self._get_processor_details(processor)
            })
        
        return dict(phases)

    def get_phase_statistics(self, phases):
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

    def _get_processor_details(self, processor):
        processor_type = self._get_processor_type(processor)
        config = processor[processor_type]
        
        details = []
        if isinstance(config, dict):
            for key, value in config.items():
                if key not in ['if', 'ignore_failure']:
                    details.append(f"{key}: {value}")
        
        return details

    def _get_processor_type(self, processor):
        meta_keys = {'if', 'ignore_failure', 'on_failure', 'tag'}
        for key in processor.keys():
            if key not in meta_keys:
                return key
        return next(iter(processor.keys()))

    def _categorize_processor(self, processor_type):
        for phase_id, phase_info in PROCESSOR_PHASES.items():
            if processor_type in phase_info['processors']:
                return phase_id
        return 'processing'