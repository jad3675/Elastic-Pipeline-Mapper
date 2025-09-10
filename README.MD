# Elasticsearch Pipeline Analyzer

A comprehensive GUI application for visualizing and analyzing Elasticsearch ingest pipeline infrastructure with multi-level interactive diagrams.

![Application Overview](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🎯 Overview

The Elasticsearch Pipeline Analyzer is a powerful desktop application that helps DevOps engineers, data engineers, and Elasticsearch administrators visualize and understand complex ingest pipeline infrastructures. It provides three distinct visualization levels to analyze pipeline relationships, processing phases, and detailed processor configurations.

### Key Problems Solved

- **Complex Pipeline Dependencies**: Understand how pipelines call each other and create processing chains
- **Enrichment Policy Relationships**: Visualize which pipelines use which enrichment policies and their source indices
- **Processor Organization**: See how processors are logically grouped within pipelines
- **Infrastructure Overview**: Get a high-level view of your entire ingest infrastructure
- **Documentation**: Generate visual documentation of your pipeline architecture

## 🆕 What's New (Modular + 3D)

- Modern modular design (no longer a single monolithic script). Clear separation of concerns across UI, data access, analysis, and visualization layers:
  - Entry point: [main.py](main.py)
  - App orchestration: [analyzer/app.py](analyzer/app.py)
  - Elasticsearch access: [analyzer/elasticsearch/connection.py](analyzer/elasticsearch/connection.py), [analyzer/elasticsearch/data_fetcher.py](analyzer/elasticsearch/data_fetcher.py)
  - Analysis: [analyzer/analysis/processor_analyzer.py](analyzer/analysis/processor_analyzer.py), [analyzer/analysis/relationship_builder.py](analyzer/analysis/relationship_builder.py)
  - Visualization (2D + 3D): [analyzer/visualization/html_generator.py](analyzer/visualization/html_generator.py)
  - UI: [analyzer/ui/*](analyzer/ui)
- New 3D force-directed visualization:
  - Distinct 3D shapes per node type (box, cylinder, cone, dodecahedron, torus, etc.)
  - Crisp labels, white background, improved lighting/shadows, and edge outlines for depth
  - 3D Mode toggle integrated into the Export panel
- Quality-of-life improvements:
  - HiDPI-friendly label rendering
  - PNG/SVG export with correct white background
  - Stable library versions for rendering to avoid API mismatches

## ✨ Features

### 🔍 Multi-Level Visualization
- **📊 Overview Level**: High-level pipeline relationships with basic statistics
- **🔧 Pipeline Detail Level**: Logical processing phases within pipelines  
- **🔬 Processor Detail Level**: Detailed processor groups and configurations

### 🌐 Interactive Network Diagrams
- **Hover Tooltips**: Quick information on mouse hover
- **Click Selection**: Select nodes to see detailed information in sidebar
- **Double-Click Details**: Full processor configuration modal
- **Drag & Drop**: Reposition nodes for better visualization
- **Zoom Controls**: Zoom in/out and reset view
- **Data Flow Animation**: Animated particles showing data flow direction

### 🧭 3D Force-Directed Visualization (New)
- Distinct 3D geometries by type for faster cognition (pipeline, index, phase, enrich, transform, templates, groups)
- Specular lighting + outlines for real depth perception
- Readable labels with pill backgrounds and HiDPI scaling
- White background (renderer + scene + CSS) for clean documentation screenshots
- 3D Mode toggle in the Export panel
- Rotate, pan, zoom interactions consistent with typical 3D scenes

### 📊 Comprehensive Analysis
- **Pipeline Chains**: Trace complete processing chains from indices
- **Processor Categorization**: Automatic grouping by logical phases:
  - 📥 Input & Parsing (grok, json, csv, dissect, etc.)
  - 🔄 Data Transformation (set, remove, rename, convert, etc.)
  - 📈 Enrichment (enrich, geoip, user_agent, etc.)
  - ⚙️ Processing & Validation (script, conditional, foreach, etc.)
  - 📋 Formatting & Output (date, fingerprint, bytes, etc.)
  - 🔗 Pipeline Orchestration (pipeline calls)

### 🔐 Flexible Authentication
- **Cloud ID**: Connect to Elastic Cloud deployments
- **URL-based**: Connect to self-hosted Elasticsearch clusters
- **API Key Authentication**: Secure API key-based access
- **Basic Authentication**: Username/password authentication
- **SSL Verification**: Optional SSL certificate verification

### 📤 Export Capabilities
- **PNG Export**: High-quality image export for documentation
- **SVG Export**: Vector graphics for scalable documentation
- **Interactive HTML**: Standalone HTML files for sharing

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager
- Internet connection for Elasticsearch access

### Required Python Packages

```bash
pip install tkinter elasticsearch vis-network
```

### Installation Steps

1. **Clone or Download**
   ```bash
   git clone <repository-url>
   cd pipelyzer
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**
- Current modular application (recommended)
```bash
python main.py
```

- Legacy single-file entry point (monolithic)
```bash
python elastic_pipeline_analyzer.py
```

## 📖 Usage Guide

### 1. Connection Setup

#### Elastic Cloud Connection
1. Select "Cloud ID" connection type
2. Enter your Elastic Cloud ID (found in your Elastic Cloud console)
3. Choose authentication method:
   - **API Key**: Enter your API key (format: `key_id:key_secret` or encoded key)
   - **Basic Auth**: Enter username and password
4. Click "Connect"

#### Self-Hosted Elasticsearch
1. Select "URL" connection type
2. Enter your Elasticsearch URL (e.g., `https://localhost:9200`)
3. Choose authentication method and enter credentials
4. Optionally disable SSL verification for development environments
5. Click "Connect"

### 2. Analysis Configuration

#### Starting Point Selection
Choose what to analyze:
- **Index**: Start from specific indices and trace their pipeline chains
- **Pipeline**: Analyze specific pipelines and their relationships
- **Enrichment Policy**: Examine enrichment policies and their usage

#### Visualization Level Selection
- **📊 Overview**: Best for understanding overall architecture and relationships
- **🔧 Pipeline Detail**: Ideal for understanding processing logic and phases
- **🔬 Processor Detail**: Perfect for detailed configuration analysis

#### Item Selection
1. Use the search box to filter available items
2. Select one or more items from the list (Ctrl+click for multiple)
3. Click "Analyze" to generate the visualization

### 3. Interactive Visualization

#### Navigation
- **Mouse Wheel**: Zoom in/out
- **Click & Drag**: Pan around the diagram
- **Node Drag**: Reposition individual nodes

#### 3D Navigation
- Left-drag: rotate the scene
- Right-drag (or Ctrl/Cmd + drag): pan
- Mouse wheel / pinch: zoom
- Double-click a node: focus the camera

#### Information Access
- **Hover**: Quick tooltip with basic information
- **Single Click**: Select node and show details in sidebar
- **Double Click**: Open detailed modal with full configuration

#### Controls
- **Zoom Controls** (Right side):
  - 🔍+ Zoom In
  - 🔍- Zoom Out  
  - 🔄 Reset View

- **Export Controls** (Left side):
  - 📷 Export PNG
  - 📄 Export SVG
  - ▶️ Show Data Flow Animation
  - 🧭 3D Mode: On/Off toggle

### 4. Understanding the Visualizations

#### Node Types
- **🗄️ Database Shape**: Elasticsearch indices
- **📦 Rectangle**: Ingest pipelines
- **🔵 Rounded Rectangle**: Enrichment policies
- **💎 Diamond**: Processing phases (Pipeline Detail level)
- **🏟️ Stadium**: Processor groups (Processor Detail level)

#### Relationship Types
- **→ default**: Default pipeline for an index
- **→ final**: Final pipeline for an index
- **→ calls**: Pipeline-to-pipeline references
- **→ enriches with**: Pipeline uses enrichment policy
- **→ uses**: General resource usage
- **→ source**: Enrichment policy source index

#### Color Coding
- **Blue (#e1f5fe)**: Indices
- **Purple (#f3e5f5)**: Pipelines
- **Green (#e8f5e8)**: Enrichment policies
- **Orange (#fff3e0)**: Processing phases
- **Pink (#fce4ec)**: Processor groups


### Application Settings
- **SSL Verification**: Can be disabled for development environments
- **Connection Timeout**: Configurable in the source code
- **Visualization Physics**: Network layout parameters can be adjusted

## 🎨 Customization

### Processor Categories
The application automatically categorizes processors into logical phases. You can modify the categorization in the `processor_phases` dictionary:

```python
self.processor_phases = {
    'input_parsing': {
        'name': '📥 Input & Parsing',
        'processors': ['grok', 'json', 'csv', 'dissect', 'kv', 'xml'],
        'color': '#e1f5fe'
    },
    # Add custom categories here
}
```

### Visual Styling
Modify colors, shapes, and styling in the HTML template generation methods:
- `generate_interactive_data()`: Node and edge styling
- `view_diagram()`: CSS styles and layout

## 🐛 Troubleshooting

### Common Issues

#### Connection Problems
**Error**: "Failed to connect to Elasticsearch"
- **Solution**: Verify your connection details, credentials, and network access
- **Check**: Elasticsearch cluster health and accessibility
- **Try**: Disabling SSL verification for development environments

#### Authentication Errors
**Error**: "Authentication failed"
- **Solution**: Verify API key format or username/password
- **Check**: User permissions for accessing indices, pipelines, and enrich policies
- **Note**: API keys should be in format `key_id:key_secret` or base64 encoded

#### Missing Data
**Error**: "No pipelines found" or empty visualizations
- **Solution**: Ensure your user has permissions to read:
  - `GET /_ingest/pipeline/*`
  - `GET /_enrich/policy/*`
  - `GET /_settings`

#### Performance Issues
**Problem**: Slow loading or rendering
- **Solution**: Limit the number of selected items for analysis
- **Try**: Use Overview level for large infrastructures
- **Consider**: Analyzing smaller subsets of your infrastructure

### Debug Mode
Enable debug logging by modifying the connection method:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🏗️ Architecture

### Modern Modular Architecture (Current)
```
main.py
analyzer/
├── app.py                         # Application bootstrap and orchestration
├── ui/
│   ├── main_frame.py
│   ├── credentials_frame.py
│   ├── analysis_frame.py
│   └── results_frame.py
├── elasticsearch/
│   ├── connection.py              # Connection/session handling
│   └── data_fetcher.py            # Cluster data retrieval
├── analysis/
│   ├── processor_analyzer.py      # Phase stats, processor grouping
│   └── relationship_builder.py    # Graph/relationship construction
├── visualization/
│   └── html_generator.py          # 2D (vis-network) + 3D (three.js/3d-force-graph) rendering
└── config/
    └── settings.py                # Tuning constants and defaults
```

- Design principles: YAGNI, SOLID, KISS, DRY
- Clear separation of concerns for maintainability and testing
- 2D and 3D visualizations share the same analyzed graph model

### Application Structure
```
elastic_pipeline_analyzer.py
├── ElasticInfrastructureGUI (Main GUI class)
├── Connection Management
│   ├── Cloud ID / URL configuration
│   ├── Authentication handling
│   └── SSL verification
├── Data Collection
│   ├── Index settings retrieval
│   ├── Pipeline configuration analysis
│   └── Enrichment policy mapping
├── Analysis Engine
│   ├── Relationship building
│   ├── Processor categorization
│   └── Chain analysis
└── Visualization
    ├── Interactive network generation
    ├── Multi-level rendering
    └── Export functionality
```

### Data Flow
1. **Connection**: Establish secure connection to Elasticsearch
2. **Collection**: Fetch indices, pipelines, and enrichment policies
3. **Analysis**: Build relationship graph and categorize processors
4. **Visualization**: Generate interactive network diagram
5. **Interaction**: Handle user interactions and provide detailed views

### Dependencies
- **tkinter**: GUI framework (built into Python)
- **elasticsearch**: Official Elasticsearch Python client
- **vis-network**: JavaScript network visualization library (2D)
- **json**: Data serialization (built into Python)
- **tempfile**: Temporary file handling (built into Python)
- **webbrowser**: Browser integration (built into Python)

Frontend (loaded via CDN in the generated HTML)
- **three.js**: 3D rendering engine
- **3d-force-graph**: Force-directed 3D graph layout
- Note: No additional Python packages are required for 3D; assets are fetched from CDNs by [analyzer/visualization/html_generator.py](analyzer/visualization/html_generator.py)

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly with different Elasticsearch configurations
5. Submit a pull request

### Code Style
- Follow PEP 8 Python style guidelines
- Use descriptive variable and method names
- Add docstrings for new methods
- Include error handling for external API calls

### Testing
Test your changes with:
- Different Elasticsearch versions (8.x, 9.x)
- Various authentication methods
- Different pipeline complexities
- Multiple visualization levels

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Elasticsearch Team**: For the excellent Python client and documentation
- **vis.js Team**: For the powerful network visualization library
- **Python Community**: For the robust ecosystem of libraries

## 📞 Support

### Getting Help
- **Issues**: Report bugs and request features via GitHub issues
- **Documentation**: Refer to Elasticsearch official documentation for pipeline syntax
- **Community**: Join Elasticsearch community forums for general questions

### Reporting Bugs
When reporting bugs, please include:
- Python version
- Elasticsearch version
- Operating system
- Error messages and stack traces
- Steps to reproduce the issue
- Sample pipeline configurations (if applicable)

## 🔮 Roadmap

### Planned Features
- **Pipeline Performance Metrics**: Integration with Elasticsearch monitoring APIs
- **Configuration Validation**: Real-time pipeline syntax validation
- **Template Support**: Support for index and component templates
- **Bulk Operations**: Batch analysis of multiple clusters
- **Export Formats**: Additional export formats (PDF, Visio, etc.)

---
