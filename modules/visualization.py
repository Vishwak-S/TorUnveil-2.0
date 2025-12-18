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
            'relay': '#45B7D1',   # Blue
            'exit': '#FFD166',    # Yellow
            'destination': '#C8C8C8',  # Gray
            'unknown': '#999999',
        }
    
    def create_simple_network_graph(self, correlation_results: pd.DataFrame, 
                                   tor_nodes_df: pd.DataFrame, 
                                   max_nodes: int = 20) -> go.Figure:
        """
        Create a simple network graph showing IP connections
        Similar to the example image provided
        """
        if correlation_results.empty or tor_nodes_df.empty:
            return self._create_empty_figure()
        
        # Filter for high confidence correlations
        high_conf = correlation_results[correlation_results['total_score'] >= 0.7]
        if high_conf.empty:
            high_conf = correlation_results
        
        # Limit number of nodes for clarity
        if len(high_conf) > max_nodes:
            high_conf = high_conf.head(max_nodes)
        
        # Create nodes
        nodes = {}
        node_positions = {}
        node_counter = 0
        
        # Add all unique IPs as nodes
        all_ips = set()
        
        # Add source IPs
        for ip in high_conf['src_ip'].unique():
            if pd.notna(ip) and ip not in all_ips:
                all_ips.add(ip)
                nodes[ip] = {
                    'id': ip,
                    'label': ip,
                    'type': 'client',
                    'color': self.colors['client'],
                    'size': 25,
                }
        
        # Add Tor nodes
        for _, row in high_conf.iterrows():
            tor_ip = row.get('tor_node_ip', '')
            if pd.notna(tor_ip) and tor_ip not in all_ips:
                all_ips.add(tor_ip)
                
                # Check if this Tor node exists in our database
                tor_info = tor_nodes_df[tor_nodes_df['ip_address'] == tor_ip]
                node_type = 'guard'
                if not tor_info.empty:
                    role = tor_info.iloc[0].get('role', '')
                    if 'Exit' in str(role):
                        node_type = 'exit'
                    elif 'Guard' in str(role):
                        node_type = 'guard'
                    else:
                        node_type = 'relay'
                
                nodes[tor_ip] = {
                    'id': tor_ip,
                    'label': tor_ip,
                    'type': node_type,
                    'color': self.colors[node_type],
                    'size': 30,
                }
        
        # Add destination IPs
        for ip in high_conf['dst_ip'].unique():
            if pd.notna(ip) and ip not in all_ips:
                all_ips.add(ip)
                nodes[ip] = {
                    'id': ip,
                    'label': ip,
                    'type': 'destination',
                    'color': self.colors['destination'],
                    'size': 20,
                }
        
        # Create edges
        edges = []
        edge_x = []
        edge_y = []
        
        for _, row in high_conf.iterrows():
            src_ip = row['src_ip']
            tor_ip = row.get('tor_node_ip', '')
            dst_ip = row['dst_ip']
            score = row.get('total_score', 0.5)
            
            if pd.notna(src_ip) and pd.notna(tor_ip) and src_ip in nodes and tor_ip in nodes:
                # Edge from source to Tor node
                edges.append({
                    'source': src_ip,
                    'target': tor_ip,
                    'score': score,
                    'width': max(1, score * 5),
                })
            
            if pd.notna(tor_ip) and pd.notna(dst_ip) and tor_ip in nodes and dst_ip in nodes:
                # Edge from Tor node to destination
                edges.append({
                    'source': tor_ip,
                    'target': dst_ip,
                    'score': score,
                    'width': max(1, score * 3),
                })
        
        # Create figure with circular layout
        fig = go.Figure()
        
        # Calculate positions in a circle
        node_list = list(nodes.keys())
        num_nodes = len(node_list)
        
        for i, node_id in enumerate(node_list):
            angle = 2 * np.pi * i / num_nodes
            radius = 2.0
            x = radius * np.cos(angle)
            y = radius * np.sin(angle)
            node_positions[node_id] = (x, y)
        
        # Add edges
        for edge in edges:
            src = edge['source']
            tgt = edge['target']
            
            if src in node_positions and tgt in node_positions:
                x0, y0 = node_positions[src]
                x1, y1 = node_positions[tgt]
                
                # Add edge trace
                fig.add_trace(go.Scatter(
                    x=[x0, x1, None],
                    y=[y0, y1, None],
                    mode='lines',
                    line=dict(
                        width=edge['width'],
                        color=f'rgba(100, 100, 100, {edge["score"] * 0.7})'
                    ),
                    hoverinfo='none',
                    showlegend=False,
                ))
        
        # Add nodes
        node_x = []
        node_y = []
        node_colors = []
        node_sizes = []
        node_texts = []
        node_labels = []
        
        for node_id in node_list:
            x, y = node_positions[node_id]
            node_x.append(x)
            node_y.append(y)
            
            node_info = nodes[node_id]
            node_colors.append(node_info['color'])
            node_sizes.append(node_info['size'])
            node_labels.append(node_info['label'])
            
            # Create hover text
            hover_text = f"<b>{node_info['label']}</b><br>"
            hover_text += f"Type: {node_info['type'].title()}<br>"
            
            # Add Tor node info if available
            if node_info['type'] in ['guard', 'relay', 'exit']:
                tor_info = tor_nodes_df[tor_nodes_df['ip_address'] == node_info['label']]
                if not tor_info.empty:
                    country = tor_info.iloc[0].get('country_name', 'Unknown')
                    bandwidth = tor_info.iloc[0].get('observed_bandwidth_mbps', 0)
                    hover_text += f"Country: {country}<br>"
                    hover_text += f"Bandwidth: {bandwidth} Mbps"
            
            node_texts.append(hover_text)
        
        # Add node trace
        fig.add_trace(go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            text=node_labels,
            textposition="top center",
            textfont=dict(
                size=10,
                color='black'
            ),
            hovertext=node_texts,
            hoverinfo='text',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='white')
            ),
            showlegend=False,
        ))
        
        # Update layout for clean appearance
        fig.update_layout(
            title='Network Graph Visualization',
            showlegend=True,
            hovermode='closest',
            margin=dict(b=0, l=0, r=0, t=40),
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                range=[-3, 3]
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                range=[-3, 3]
            ),
            height=500,
            plot_bgcolor='white',
            paper_bgcolor='white',
        )
        
        # Add legend
        self._add_simple_legend(fig)
        
        return fig
    
    def _add_simple_legend(self, fig: go.Figure):
        """Add a simple legend to the figure"""
        legend_items = [
            ('Client IP', self.colors['client']),
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
    
    def _create_empty_figure(self) -> go.Figure:
        """Create an empty figure placeholder"""
        fig = go.Figure()
        fig.update_layout(
            title="No data available for visualization",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=400,
            plot_bgcolor='white',
        )
        return fig
    
    def create_compact_network_diagram(self, correlation_results: pd.DataFrame) -> go.Figure:
        """
        Create a compact network diagram showing just IP connections
        Very similar to the provided example image
        """
        if correlation_results.empty:
            return self._create_empty_figure()
        
        # Take top correlations
        top_corr = correlation_results.nlargest(10, 'total_score')
        
        # Collect all unique IPs
        ip_addresses = set()
        
        for _, row in top_corr.iterrows():
            ip_addresses.add(str(row['src_ip']))
            ip_addresses.add(str(row['tor_node_ip']))
            ip_addresses.add(str(row['dst_ip']))
        
        ip_list = list(ip_addresses)
        
        # Create matrix layout (grid-like)
        fig = go.Figure()
        
        # Simple grid layout
        num_cols = 3
        positions = {}
        
        for i, ip in enumerate(ip_list):
            row = i // num_cols
            col = i % num_cols
            positions[ip] = (col * 4, -row * 4)
        
        # Add connections (edges)
        for _, row in top_corr.iterrows():
            src_ip = str(row['src_ip'])
            tor_ip = str(row['tor_node_ip'])
            dst_ip = str(row['dst_ip'])
            score = row['total_score']
            
            if src_ip in positions and tor_ip in positions:
                x0, y0 = positions[src_ip]
                x1, y1 = positions[tor_ip]
                
                fig.add_trace(go.Scatter(
                    x=[x0, x1, None],
                    y=[y0, y1, None],
                    mode='lines',
                    line=dict(
                        width=max(1, score * 4),
                        color='rgba(100, 149, 237, 0.6)'  # Cornflower blue
                    ),
                    hoverinfo='none',
                    showlegend=False,
                ))
            
            if tor_ip in positions and dst_ip in positions:
                x0, y0 = positions[tor_ip]
                x1, y1 = positions[dst_ip]
                
                fig.add_trace(go.Scatter(
                    x=[x0, x1, None],
                    y=[y0, y1, None],
                    mode='lines',
                    line=dict(
                        width=max(1, score * 3),
                        color='rgba(255, 165, 0, 0.6)'  # Orange
                    ),
                    hoverinfo='none',
                    showlegend=False,
                ))
        
        # Add nodes (IP addresses)
        node_x = []
        node_y = []
        node_texts = []
        node_colors = []
        
        for ip in ip_list:
            x, y = positions[ip]
            node_x.append(x)
            node_y.append(y)
            node_texts.append(ip)
            
            # Determine node color based on IP type
            if ip.startswith('192.168.'):
                node_colors.append(self.colors['client'])  # Client IPs
            elif ip in top_corr['tor_node_ip'].values:
                node_colors.append(self.colors['guard'])   # Tor nodes
            else:
                node_colors.append(self.colors['destination'])  # Destinations
        
        # Add nodes
        fig.add_trace(go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            text=node_texts,
            textposition="top center",
            textfont=dict(
                size=9,
                family='monospace'
            ),
            hovertext=[f"IP: {ip}" for ip in ip_list],
            hoverinfo='text',
            marker=dict(
                size=25,
                color=node_colors,
                line=dict(width=2, color='white')
            ),
            showlegend=False,
        ))
        
        # Update layout for clean look
        fig.update_layout(
            title="Network Connections",
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=20, r=20, t=40),
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
            ),
            height=400,
            width=600,
            plot_bgcolor='white',
        )
        
        return fig

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