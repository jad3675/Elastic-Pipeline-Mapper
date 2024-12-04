
# Elasticsearch Pipeline Analyzer

A Python-based GUI application for visualizing and analyzing Elasticsearch ingest pipeline relationships, enrichment policies, and index configurations.

## Features

- **Interactive GUI Interface**: Built with Tkinter for a user-friendly experience
- **Elasticsearch Connection Management**: Secure connection using Cloud ID and API credentials
- **Comprehensive Analysis**: Visualize relationships between:
  - Indices and their pipeline configurations
  - Ingest pipelines and their processor chains
  - Enrichment policies and their source indices
- **Advanced Visualization**:
  - Interactive Mermaid.js diagrams
  - Zoom controls for large diagrams
  - Export capabilities (PNG/SVG)
  - Color-coded components for easy identification
  - Detailed tooltips with component information

## Prerequisites

- Python 3.x
- Required Python packages:
  ```
  elasticsearch
  tkinter (usually comes with Python)
  ```

## Installation

1. Clone the repository or download the source code
2. Install required dependencies:
   ```bash
   pip install elasticsearch
   ```

## Usage

1. Run the application:
   ```bash
   python elasticsearch_pipeline_analyzer.py
   ```

2. Connect to Elasticsearch:
   - Enter your Cloud ID
   - Provide API Key and Secret
   - Click "Connect"

3. Analyze Infrastructure:
   - Select analysis type (Index/Pipeline/Enrichment Policy)
   - Choose components to analyze
   - Click "Analyze" to generate visualization
   - Use "View Diagram" for interactive visualization

## Visualization Features

### Node Types
- **Indices**: Database-shaped nodes (Light green)
- **Pipelines**: Rectangular nodes (Light purple)
- **Enrichment Policies**: Rounded rectangles (Light pink)
- **Processors**: Diamond shapes (Light violet)

### Relationship Types
- Default Pipeline connections
- Final Pipeline connections
- Pipeline references
- Enrichment process connections
- Source index relationships

### Interactive Features
- Zoom in/out controls
- PNG/SVG export options
- Hover tooltips with detailed information
- Scrollable and pannable diagram view

## Component Details

### Main Classes

#### ElasticInfrastructureGUI
The main application class handling:
- GUI initialization
- Elasticsearch connections
- Data analysis and visualization
- User interactions

### Key Methods

- `connect_to_elasticsearch()`: Establishes connection to Elasticsearch cluster
- `fetch_infrastructure_data()`: Retrieves configuration data
- `build_relationships()`: Analyzes component relationships
- `generate_mermaid_diagram()`: Creates visualization code
- `view_diagram()`: Renders interactive diagram

## Security Considerations

- API credentials are handled securely
- No credentials are stored persistently
- Secure HTTPS connections to Elasticsearch
- Input validation for all user inputs

## Customization

The application supports customization through:
- Modifiable node styles
- Adjustable diagram layouts
- Configurable relationship displays
- Custom color schemes

## Troubleshooting

Common issues and solutions:

1. **Connection Failed**
   - Verify Cloud ID format
   - Check API credentials
   - Ensure network connectivity

2. **Diagram Not Displaying**
   - Check browser compatibility
   - Verify JavaScript is enabled
   - Ensure sufficient memory for large diagrams

3. **Export Issues**
   - Try alternative export format
   - Reduce diagram complexity if needed
   - Ensure sufficient disk space

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Uses Mermaid.js for diagram generation
- Built with Python's Tkinter library
- Elasticsearch client library

## Support

For issues, questions, or contributions, please:
1. Check existing issues
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected behavior
   - System information
