# Template categorization for visualization
TEMPLATE_TYPES = {
    'index_template': {
        'name': '📋 Index Template',
        'color': '#e8eaf6',
        'shape': 'hexagon'
    },
    'component_template': {
        'name': '🧩 Component Template', 
        'color': '#f1f8e9',
        'shape': 'triangle'
    }
}

# Processor categorization mapping
PROCESSOR_PHASES = {
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