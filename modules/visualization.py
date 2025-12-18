"""
visualization.py - Network visualization for TOR-Unveil
Creates interactive visualizations for network paths and correlations
"""

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Tuple, Optional, Any
import json
import networkx as nx
from datetime import datetime
import colorsys
import os

class NetworkVisualizer:
    """Creates interactive network visualizations for TOR-Unveil"""
    
    def __init__(self):
        self.colors = {
            'client': '#FF6B6B',  # Red
            'guard': '#4ECDC4',   # Teal
            'relay': '#95E1D3',   # Light green
            'exit': '#FFD166',    # Yellow
            'destination': '#C8C8C8',  # Gray
            'unknown': '#999999',
            'high_confidence': '#10B981',  # Green
            'medium_confidence': '#F59E0B',  # Yellow
            'low_confidence': '#EF4444',  # Red
        }
    
    def create_network_graph(self, paths_data: Dict) -> Dict:
        """
        Create network graph data from reconstructed paths
        
        Args:
            paths_data: Dictionary with reconstructed paths
            
        Returns:
            Dictionary with nodes and edges for visualization
        """
        if not paths_data or not paths_data.get('paths'):
            print("⚠️  No paths data for network graph")
            return self._create_empty_graph()
        
        print("🎨 Creating network graph visualization...")
        
        # Initialize graph
        G = nx.Graph()
        nodes = []
        edges = []
        
        # Add nodes from all paths
        node_counter = 0
        node_positions = {}
        
        for path in paths_data['paths']:
            path_nodes = path.get('nodes', [])
            
            for i, node in enumerate(path_nodes):
                node_id = node.get('ip', f'node_{node_counter}')
                node_type = node.get('type', 'unknown')
                
                # Create node if not exists
                if not G.has_node(node_id):
                    # Calculate position (circular layout for now)
                    angle = (node_counter * 2 * np.pi) / max(len(paths_data['paths']) * 5, 1)
                    radius = 300
                    x = radius * np.cos(angle)
                    y = radius * np.sin(angle)
                    
                    node_data = {
                        'id': node_id,
                        'label': node.get('label', node_id),
                        'type': node_type,
                        'color': self.colors.get(node_type, self.colors['unknown']),
                        'size': self._calculate_node_size(node),
                        'x': x,
                        'y': y,
                        'tooltip': self._create_node_tooltip(node),
                        'metadata': node,
                    }
                    
                    nodes.append(node_data)
                    G.add_node(node_id, **node_data)
                    node_positions[node_id] = (x, y)
                    node_counter += 1
                
                # Add edge to next node in path
                if i < len(path_nodes) - 1:
                    next_node = path_nodes[i + 1]
                    next_node_id = next_node.get('ip', f'node_{node_counter}')
                    
                    edge_id = f"{node_id}_{next_node_id}"
                    if not G.has_edge(node_id, next_node_id):
                        edge_data = {
                            'id': edge_id,
                            'source': node_id,
                            'target': next_node_id,
                            'width': self._calculate_edge_width(path),
                            'color': self._get_edge_color(path),
                            'label': f"Path {path.get('path_id', '')[:6]}...",
                            'tooltip': self._create_edge_tooltip(path, node, next_node),
                        }
                        
                        edges.append(edge_data)
                        G.add_edge(node_id, next_node_id, **edge_data)
        
        # Improve layout if we have nodes
        if nodes:
            nodes = self._improve_layout(nodes, edges)
        
        result = {
            'nodes': nodes,
            'edges': edges,
            'metadata': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'generated_at': datetime.now().isoformat(),
            }
        }
        
        print(f"✅ Created network graph with {len(nodes)} nodes and {len(edges)} edges")
        return result
    
    def _calculate_node_size(self, node: Dict) -> int:
        """Calculate node size based on its properties"""
        base_size = 20
        
        # Adjust based on node type
        node_type = node.get('type', '')
        if node_type == 'client' or node_type == 'destination':
            return base_size * 1.5
        elif node_type == 'guard' or node_type == 'exit':
            return base_size * 2
        elif node_type == 'relay':
            return base_size
        
        # Adjust based on bandwidth if available
        bandwidth = node.get('bandwidth_mbps', 0)
        if bandwidth > 100:
            return base_size * 3
        elif bandwidth > 50:
            return base_size * 2
        
        return base_size
    
    def _calculate_edge_width(self, path: Dict) -> int:
        """Calculate edge width based on path confidence"""
        confidence = path.get('avg_confidence', 0.5)
        
        # Width from 1 to 5 based on confidence
        return max(1, min(5, int(confidence * 10)))
    
    def _get_edge_color(self, path: Dict) -> str:
        """Get edge color based on path confidence"""
        confidence = path.get('avg_confidence', 0.5)
        
        if confidence >= 0.8:
            return self.colors['high_confidence']
        elif confidence >= 0.6:
            return self.colors['medium_confidence']
        else:
            return self.colors['low_confidence']
    
    def _create_node_tooltip(self, node: Dict) -> str:
        """Create tooltip text for a node"""
        tooltip = f"<b>{node.get('nickname', 'Node')}</b><br>"
        tooltip += f"Type: {node.get('type', 'unknown').title()}<br>"
        tooltip += f"IP: {node.get('ip', 'N/A')}<br>"
        
        if node.get('country') and node.get('country') != 'Unknown':
            tooltip += f"Country: {node.get('country')}<br>"
        
        if node.get('bandwidth_mbps', 0) > 0:
            tooltip += f"Bandwidth: {node.get('bandwidth_mbps')} Mbps<br>"
        
        if node.get('performance_score', 0) > 0:
            tooltip += f"Performance: {node.get('performance_score'):.2f}<br>"
        
        return tooltip
    
    def _create_edge_tooltip(self, path: Dict, source_node: Dict, target_node: Dict) -> str:
        """Create tooltip text for an edge"""
        tooltip = f"<b>Path Connection</b><br>"
        tooltip += f"From: {source_node.get('nickname', source_node.get('ip', '?'))}<br>"
        tooltip += f"To: {target_node.get('nickname', target_node.get('ip', '?'))}<br>"
        tooltip += f"Path Confidence: {path.get('avg_confidence', 0):.2f}<br>"
        
        if path.get('complete', False):
            tooltip += "Status: Complete Path<br>"
        else:
            tooltip += "Status: Incomplete Path<br>"
        
        return tooltip
    
    def _improve_layout(self, nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
        """Improve node layout using force-directed simulation"""
        try:
            # Create NetworkX graph for layout calculation
            G = nx.Graph()
            
            # Add nodes
            for node in nodes:
                G.add_node(node['id'], pos=(node['x'], node['y']))
            
            # Add edges
            for edge in edges:
                G.add_edge(edge['source'], edge['target'])
            
            # Use spring layout for better visualization
            if len(nodes) > 1:
                pos = nx.spring_layout(G, seed=42, k=2, iterations=50)
                
                # Update node positions
                for node in nodes:
                    if node['id'] in pos:
                        node['x'] = pos[node['id']][0] * 400  # Scale up
                        node['y'] = pos[node['id']][1] * 400
            
        except Exception as e:
            print(f"⚠️  Error in layout improvement: {e}")
        
        return nodes
    
    def _create_empty_graph(self) -> Dict:
        """Create empty graph structure"""
        return {
            'nodes': [],
            'edges': [],
            'metadata': {
                'total_nodes': 0,
                'total_edges': 0,
                'generated_at': datetime.now().isoformat(),
            }
        }
    
    def create_plotly_network(self, graph_data: Dict) -> go.Figure:
        """
        Create Plotly figure for network visualization
        
        Args:
            graph_data: Dictionary with nodes and edges
            
        Returns:
            Plotly Figure object
        """
        if not graph_data or not graph_data['nodes']:
            # Return empty figure
            fig = go.Figure()
            fig.update_layout(
                title="No network data available",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=500,
            )
            return fig
        
        nodes = graph_data['nodes']
        edges = graph_data['edges']
        
        # Create edge traces
        edge_x = []
        edge_y = []
        edge_colors = []
        edge_widths = []
        
        for edge in edges:
            source_node = next((n for n in nodes if n['id'] == edge['source']), None)
            target_node = next((n for n in nodes if n['id'] == edge['target']), None)
            
            if source_node and target_node:
                edge_x.extend([source_node['x'], target_node['x'], None])
                edge_y.extend([source_node['y'], target_node['y'], None])
                edge_colors.append(edge.get('color', '#CCCCCC'))
                edge_widths.append(edge.get('width', 1))
        
        # Create edge trace
        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            mode='lines',
            line=dict(
                width=edge_widths[0] if edge_widths else 1,
                color=edge_colors[0] if edge_colors else '#CCCCCC'
            ),
            hoverinfo='none',
            showlegend=False,
        )
        
        # Prepare node data
        node_x = [node['x'] for node in nodes]
        node_y = [node['y'] for node in nodes]
        node_colors = [node['color'] for node in nodes]
        node_sizes = [node['size'] for node in nodes]
        node_texts = [node['tooltip'] for node in nodes]
        node_labels = [node['label'] for node in nodes]
        
        # Create node trace
        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            text=node_labels,
            textposition="top center",
            hovertext=node_texts,
            hoverinfo='text',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white')
            ),
            showlegend=False,
        )
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace])
        
        # Update layout
        fig.update_layout(
            title='TOR Network Path Visualization',
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=600,
            plot_bgcolor='white',
        )
        
        # Add legend for node types
        self._add_node_legend(fig)
        
        return fig
    
    def _add_node_legend(self, fig: go.Figure):
        """Add legend for node types to the figure"""
        legend_items = [
            ('Client', self.colors['client']),
            ('Guard Node', self.colors['guard']),
            ('Relay Node', self.colors['relay']),
            ('Exit Node', self.colors['exit']),
            ('Destination', self.colors['destination']),
        ]
        
        # Add invisible traces for legend
        for label, color in legend_items:
            fig.add_trace(go.Scatter(
                x=[None],
                y=[None],
                mode='markers',
                marker=dict(size=10, color=color),
                name=label,
                showlegend=True
            ))
    
    def create_correlation_heatmap(self, correlation_results: pd.DataFrame) -> go.Figure:
        """
        Create heatmap of correlation scores
        
        Args:
            correlation_results: DataFrame with correlation scores
            
        Returns:
            Plotly Figure object with heatmap
        """
        if correlation_results.empty:
            fig = go.Figure()
            fig.update_layout(
                title="No correlation data available",
                height=400,
            )
            return fig
        
        # Prepare data for heatmap
        # Group by source IP and Tor node country
        heatmap_data = correlation_results.groupby(['src_ip', 'tor_node_country']).agg({
            'total_score': 'mean'
        }).unstack(fill_value=0)
        
        # Flatten column names
        heatmap_data.columns = [col[1] for col in heatmap_data.columns]
        
        # Create heatmap
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns.tolist(),
            y=heatmap_data.index.tolist(),
            colorscale='RdYlGn',
            zmin=0,
            zmax=1,
            colorbar=dict(title='Correlation Score'),
            hoverongaps=False,
            text=heatmap_data.values.round(3),
            texttemplate='%{text}',
            textfont={"size": 10},
        ))
        
        fig.update_layout(
            title='Correlation Heatmap: Source IP vs Tor Node Country',
            xaxis_title='Tor Node Country',
            yaxis_title='Source IP',
            height=500,
            width=800,
        )
        
        return fig
    
    def create_score_distribution(self, correlation_results: pd.DataFrame) -> go.Figure:
        """
        Create distribution of correlation scores
        
        Args:
            correlation_results: DataFrame with correlation scores
            
        Returns:
            Plotly Figure object with distribution
        """
        if correlation_results.empty:
            fig = go.Figure()
            fig.update_layout(
                title="No correlation data available",
                height=400,
            )
            return fig
        
        # Create histogram
        fig = go.Figure()
        
        fig.add_trace(go.Histogram(
            x=correlation_results['total_score'],
            nbinsx=20,
            name='All Correlations',
            marker_color=self.colors['medium_confidence'],
            opacity=0.7,
        ))
        
        # Add vertical lines for confidence thresholds
        fig.add_vline(x=0.8, line_dash="dash", line_color=self.colors['high_confidence'],
                     annotation_text="High Confidence", annotation_position="top right")
        fig.add_vline(x=0.6, line_dash="dash", line_color=self.colors['medium_confidence'],
                     annotation_text="Medium Confidence", annotation_position="top right")
        fig.add_vline(x=0.4, line_dash="dash", line_color=self.colors['low_confidence'],
                     annotation_text="Low Confidence", annotation_position="top right")
        
        fig.update_layout(
            title='Distribution of Correlation Scores',
            xaxis_title='Correlation Score',
            yaxis_title='Count',
            height=400,
            bargap=0.1,
        )
        
        return fig
    
    def create_path_length_chart(self, paths_data: Dict) -> go.Figure:
        """
        Create chart showing path length distribution
        
        Args:
            paths_data: Dictionary with reconstructed paths
            
        Returns:
            Plotly Figure object
        """
        if not paths_data or not paths_data.get('paths'):
            fig = go.Figure()
            fig.update_layout(
                title="No path data available",
                height=400,
            )
            return fig
        
        # Extract path lengths
        path_lengths = [len(p.get('nodes', [])) for p in paths_data['paths']]
        
        # Create bar chart
        fig = go.Figure(data=[
            go.Histogram(
                x=path_lengths,
                nbinsx=max(5, len(set(path_lengths))),
                marker_color=self.colors['guard'],
                opacity=0.7,
            )
        ])
        
        fig.update_layout(
            title='Distribution of Path Lengths (Number of Hops)',
            xaxis_title='Path Length (Hops)',
            yaxis_title='Number of Paths',
            height=400,
            bargap=0.1,
        )
        
        return fig
    
    def create_country_distribution(self, tor_nodes_df: pd.DataFrame) -> go.Figure:
        """
        Create bar chart of Tor node distribution by country
        
        Args:
            tor_nodes_df: DataFrame with Tor node information
            
        Returns:
            Plotly Figure object
        """
        if tor_nodes_df.empty:
            fig = go.Figure()
            fig.update_layout(
                title="No Tor node data available",
                height=400,
            )
            return fig
        
        # Count nodes by country
        country_counts = tor_nodes_df['country_name'].value_counts().reset_index()
        country_counts.columns = ['Country', 'Node Count']
        
        # Create bar chart
        fig = px.bar(
            country_counts.head(15),  # Top 15 countries
            x='Country',
            y='Node Count',
            title='Top 15 Countries by Tor Node Count',
            color='Node Count',
            color_continuous_scale='Blues',
        )
        
        fig.update_layout(
            height=500,
            xaxis_tickangle=-45,
        )
        
        return fig
    
    def save_visualization(self, fig: go.Figure, filename: str = None) -> str:
        """
        Save visualization to HTML file
        
        Args:
            fig: Plotly Figure object
            filename: Output filename (optional)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            filename = os.path.join("data", "visualizations", f"network_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Save as HTML
            fig.write_html(filename)
            print(f"💾 Saved visualization to {filename}")
            return filename
            
        except Exception as e:
            print(f"❌ Error saving visualization: {e}")
            return ""

# Test function
def test_visualization_module():
    """Test the visualization module"""
    print("🧪 Testing visualization module...")
    print("="*60)
    
    # Create sample data
    print("📝 Creating sample data...")
    
    # Sample paths data
    paths_data = {
        'paths': [
            {
                'path_id': 'path_001',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'avg_confidence': 0.85,
                'complete': True,
                'nodes': [
                    {'ip': '192.168.1.100', 'type': 'client', 'nickname': 'Client', 'country': 'Local'},
                    {'ip': '185.220.101.1', 'type': 'guard', 'nickname': 'Guard1', 'country': 'Germany', 'bandwidth_mbps': 50},
                    {'ip': '185.220.101.10', 'type': 'relay', 'nickname': 'Relay1', 'country': 'US', 'bandwidth_mbps': 30},
                    {'ip': '185.220.101.20', 'type': 'exit', 'nickname': 'Exit1', 'country': 'Netherlands', 'bandwidth_mbps': 100},
                    {'ip': '10.0.0.1', 'type': 'destination', 'nickname': 'Dest1', 'country': 'Unknown'},
                ]
            },
            {
                'path_id': 'path_002',
                'src_ip': '192.168.1.101',
                'dst_ip': '10.0.0.2',
                'avg_confidence': 0.65,
                'complete': False,
                'nodes': [
                    {'ip': '192.168.1.101', 'type': 'client', 'nickname': 'Client2', 'country': 'Local'},
                    {'ip': '185.220.101.2', 'type': 'guard', 'nickname': 'Guard2', 'country': 'US', 'bandwidth_mbps': 80},
                    {'ip': '185.220.101.11', 'type': 'relay', 'nickname': 'Relay2', 'country': 'Germany', 'bandwidth_mbps': 40},
                    {'ip': '10.0.0.2', 'type': 'destination', 'nickname': 'Dest2', 'country': 'Unknown'},
                ]
            }
        ],
        'statistics': {
            'total_paths': 2,
            'complete_paths': 1,
            'avg_path_length': 4.5,
        }
    }
    
    # Sample correlation data
    correlation_data = {
        'src_ip': ['192.168.1.100', '192.168.1.100', '192.168.1.101', '192.168.1.101'],
        'tor_node_country': ['Germany', 'US', 'Germany', 'Netherlands'],
        'total_score': [0.85, 0.72, 0.65, 0.58],
    }
    correlation_df = pd.DataFrame(correlation_data)
    
    # Sample Tor nodes data
    tor_nodes_data = {
        'country_name': ['Germany', 'US', 'Netherlands', 'France', 'UK'] * 4,
        'observed_bandwidth_mbps': np.random.randint(10, 100, 20),
    }
    tor_nodes_df = pd.DataFrame(tor_nodes_data)
    
    print("✅ Created sample data")
    
    # Test visualization functions
    print("\n🎨 Testing visualization functions...")
    visualizer = NetworkVisualizer()
    
    # Test network graph creation
    print("1. Testing network graph creation...")
    graph_data = visualizer.create_network_graph(paths_data)
    if graph_data and graph_data['nodes']:
        print(f"   ✅ Created graph with {len(graph_data['nodes'])} nodes")
    else:
        print("   ❌ Failed to create graph")
    
    # Test Plotly network
    print("2. Testing Plotly network visualization...")
    try:
        fig = visualizer.create_plotly_network(graph_data)
        print("   ✅ Created Plotly network figure")
    except Exception as e:
        print(f"   ❌ Failed to create Plotly figure: {e}")
    
    # Test heatmap
    print("3. Testing correlation heatmap...")
    try:
        heatmap_fig = visualizer.create_correlation_heatmap(correlation_df)
        print("   ✅ Created correlation heatmap")
    except Exception as e:
        print(f"   ❌ Failed to create heatmap: {e}")
    
    # Test score distribution
    print("4. Testing score distribution...")
    try:
        dist_fig = visualizer.create_score_distribution(correlation_df)
        print("   ✅ Created score distribution")
    except Exception as e:
        print(f"   ❌ Failed to create distribution: {e}")
    
    # Test path length chart
    print("5. Testing path length chart...")
    try:
        path_fig = visualizer.create_path_length_chart(paths_data)
        print("   ✅ Created path length chart")
    except Exception as e:
        print(f"   ❌ Failed to create path chart: {e}")
    
    # Test country distribution
    print("6. Testing country distribution...")
    try:
        country_fig = visualizer.create_country_distribution(tor_nodes_df)
        print("   ✅ Created country distribution")
    except Exception as e:
        print(f"   ❌ Failed to create country chart: {e}")
    
    # Test saving visualization
    print("7. Testing visualization saving...")
    try:
        test_fig = go.Figure(data=[go.Bar(x=['A', 'B', 'C'], y=[1, 2, 3])])
        saved_file = visualizer.save_visualization(test_fig, "test_visualization.html")
        if saved_file and os.path.exists(saved_file):
            print(f"   ✅ Saved visualization to {saved_file}")
            os.remove(saved_file)  # Clean up
        else:
            print("   ❌ Failed to save visualization")
    except Exception as e:
        print(f"   ❌ Error saving visualization: {e}")
    
    print("\n✅ Visualization module test COMPLETE!")
    return True

if __name__ == "__main__":
    # Run test
    test_visualization_module()