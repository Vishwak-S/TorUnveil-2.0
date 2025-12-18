"""
path_reconstructor.py - Network path reconstruction for TOR-Unveil
Reconstructs probable Tor paths from correlation results
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, deque
import random
import hashlib
import os

class PathReconstructor:
    """Reconstructs probable Tor network paths from correlation results"""
    
    def __init__(self, max_path_length=6, min_confidence=0.4):
        self.max_path_length = max_path_length
        self.min_confidence = min_confidence
        self.reconstructed_paths = []
        
    def reconstruct_paths(self, correlation_results: pd.DataFrame, tor_nodes_df: pd.DataFrame) -> Dict:
        """
        Reconstruct network paths from correlation results
        
        Args:
            correlation_results: DataFrame with correlation scores
            tor_nodes_df: DataFrame with Tor node information
            
        Returns:
            Dictionary with reconstructed paths and statistics
        """
        print("🔄 Reconstructing network paths...")
        
        if correlation_results.empty:
            print("❌ No correlation results to reconstruct paths from")
            return self._create_empty_result()
        
        # Filter high-confidence correlations
        high_conf_correlations = correlation_results[
            correlation_results['total_score'] >= self.min_confidence
        ].copy()
        
        if high_conf_correlations.empty:
            print(f"⚠️  No correlations with confidence >= {self.min_confidence}")
            return self._create_empty_result()
        
        print(f"📊 Using {len(high_conf_correlations)} high-confidence correlations")
        
        # Group correlations by source IP
        source_groups = high_conf_correlations.groupby('src_ip')
        
        # Reconstruct paths for each source
        all_paths = []
        for src_ip, group in source_groups:
            paths_for_source = self._reconstruct_paths_for_source(
                src_ip, group, tor_nodes_df
            )
            all_paths.extend(paths_for_source)
        
        # Calculate statistics
        stats = self._calculate_path_statistics(all_paths)
        
        result = {
            'paths': all_paths,
            'statistics': stats,
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_paths': len(all_paths),
                'min_confidence': self.min_confidence,
                'max_path_length': self.max_path_length,
            }
        }
        
        print(f"✅ Reconstructed {len(all_paths)} network paths")
        print(f"📈 Complete paths: {stats.get('complete_paths', 0)}")
        print(f"📊 Average path length: {stats.get('avg_path_length', 0):.1f} hops")
        
        return result
    
    def _reconstruct_paths_for_source(self, src_ip: str, 
                                    correlations: pd.DataFrame,
                                    tor_nodes_df: pd.DataFrame) -> List[Dict]:
        """Reconstruct paths for a specific source IP"""
        paths = []
        
        # Get unique destination IPs for this source
        unique_dsts = correlations['dst_ip'].unique()
        
        for dst_ip in unique_dsts[:5]:  # Limit to first 5 destinations
            # Get correlations for this source-destination pair
            src_dst_correlations = correlations[correlations['dst_ip'] == dst_ip]
            
            # Sort by confidence
            src_dst_correlations = src_dst_correlations.sort_values('total_score', ascending=False)
            
            # Take top N correlations for path reconstruction
            top_correlations = src_dst_correlations.head(3)
            
            for _, corr in top_correlations.iterrows():
                path = self._reconstruct_single_path(corr, tor_nodes_df)
                if path:
                    paths.append(path)
        
        return paths
    
    def _reconstruct_single_path(self, correlation: pd.Series, 
                                tor_nodes_df: pd.DataFrame) -> Optional[Dict]:
        """Reconstruct a single network path from correlation"""
        try:
            # Extract correlation data
            src_ip = correlation.get('src_ip', '')
            dst_ip = correlation.get('dst_ip', '')
            entry_node_ip = correlation.get('tor_node_ip', '')
            confidence = correlation.get('total_score', 0)
            
            if not src_ip or not entry_node_ip:
                return None
            
            # Create path object
            path = {
                'path_id': self._generate_path_id(src_ip, dst_ip, entry_node_ip),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'confidence': confidence,
                'entry_node_ip': entry_node_ip,
                'nodes': [],
                'complete': False,
                'timestamp': datetime.now().isoformat(),
            }
            
            # Get entry node details
            entry_node = tor_nodes_df[tor_nodes_df['ip_address'] == entry_node_ip]
            if not entry_node.empty:
                entry_node_data = entry_node.iloc[0].to_dict()
                path['entry_node'] = self._create_node_object(entry_node_data, 'guard')
                path['nodes'].append(path['entry_node'])
            
            # Find middle nodes (simulated - in reality would need more data)
            middle_nodes = self._find_middle_nodes(entry_node_ip, tor_nodes_df)
            for middle_node in middle_nodes:
                path['nodes'].append(middle_node)
            
            # Find exit node (simulated)
            exit_node = self._find_exit_node(tor_nodes_df)
            if exit_node:
                path['exit_node'] = exit_node
                path['nodes'].append(exit_node)
                path['complete'] = True
            
            # Add destination as final node
            path['nodes'].append(self._create_destination_node(dst_ip))
            
            # Calculate path metrics
            path['total_hops'] = len(path['nodes'])
            path['avg_confidence'] = self._calculate_path_confidence(path, correlation)
            
            return path
            
        except Exception as e:
            print(f"⚠️  Error reconstructing path: {e}")
            return None
    
    def _find_middle_nodes(self, entry_node_ip: str, 
                          tor_nodes_df: pd.DataFrame) -> List[Dict]:
        """Find middle nodes for the path (simulated)"""
        middle_nodes = []
        
        # Get nodes that are not guards or exits
        middle_candidates = tor_nodes_df[
            (tor_nodes_df['is_guard'] == 0) & 
            (tor_nodes_df['is_exit'] == 0) &
            (tor_nodes_df['ip_address'] != entry_node_ip)
        ]
        
        if not middle_candidates.empty:
            # Select 1-3 random middle nodes
            num_middle = random.randint(1, min(3, len(middle_candidates)))
            selected = middle_candidates.sample(num_middle)
            
            for _, node in selected.iterrows():
                middle_nodes.append(self._create_node_object(node.to_dict(), 'relay'))
        
        return middle_nodes
    
    def _find_exit_node(self, tor_nodes_df: pd.DataFrame) -> Optional[Dict]:
        """Find an exit node for the path (simulated)"""
        exit_candidates = tor_nodes_df[tor_nodes_df['is_exit'] == 1]
        
        if not exit_candidates.empty:
            exit_node = exit_candidates.sample(1).iloc[0]
            return self._create_node_object(exit_node.to_dict(), 'exit')
        
        return None
    
    def _create_node_object(self, node_data: Dict, node_type: str) -> Dict:
        """Create a standardized node object"""
        return {
            'ip': node_data.get('ip_address', ''),
            'nickname': node_data.get('nickname', 'Unknown'),
            'type': node_type,
            'role': node_data.get('role', ''),
            'country': node_data.get('country_name', 'Unknown'),
            'bandwidth_mbps': node_data.get('observed_bandwidth_mbps', 0),
            'performance_score': node_data.get('performance_score', 0),
            'label': f"{node_data.get('nickname', 'Node')} ({node_type})",
            'tooltip': f"{node_data.get('nickname', 'Node')}\n"
                      f"Type: {node_type}\n"
                      f"Country: {node_data.get('country_name', 'Unknown')}\n"
                      f"Bandwidth: {node_data.get('observed_bandwidth_mbps', 0)} Mbps\n"
                      f"Role: {node_data.get('role', '')}",
        }
    
    def _create_destination_node(self, dst_ip: str) -> Dict:
        """Create a destination node object"""
        return {
            'ip': dst_ip,
            'nickname': f'Dest: {dst_ip}',
            'type': 'destination',
            'role': 'Destination',
            'country': 'Unknown',
            'bandwidth_mbps': 0,
            'performance_score': 0,
            'label': f'Destination\n{dst_ip}',
            'tooltip': f"Destination Server\nIP: {dst_ip}",
        }
    
    def _calculate_path_confidence(self, path: Dict, correlation: pd.Series) -> float:
        """Calculate overall confidence for the path"""
        # Base confidence from correlation
        confidence = correlation.get('total_score', 0)
        
        # Adjust based on path completeness
        if path.get('complete', False):
            confidence *= 1.1  # 10% bonus for complete paths
        
        # Adjust based on number of hops (optimal is 3-5)
        num_hops = len(path.get('nodes', []))
        if 3 <= num_hops <= 5:
            confidence *= 1.05  # 5% bonus for optimal path length
        elif num_hops > 6:
            confidence *= 0.9  # 10% penalty for long paths
        
        return min(1.0, confidence)
    
    def _generate_path_id(self, src_ip: str, dst_ip: str, entry_ip: str) -> str:
        """Generate unique path ID"""
        path_str = f"{src_ip}_{dst_ip}_{entry_ip}_{datetime.now().timestamp()}"
        return hashlib.md5(path_str.encode()).hexdigest()[:12]
    
    def _calculate_path_statistics(self, paths: List[Dict]) -> Dict:
        """Calculate statistics about reconstructed paths"""
        if not paths:
            return {}
        
        total_paths = len(paths)
        complete_paths = sum(1 for p in paths if p.get('complete', False))
        
        # Calculate average path length
        path_lengths = [len(p.get('nodes', [])) for p in paths]
        avg_path_length = np.mean(path_lengths) if path_lengths else 0
        
        # Calculate confidence statistics
        confidences = [p.get('avg_confidence', 0) for p in paths]
        avg_confidence = np.mean(confidences) if confidences else 0
        
        # Count nodes by type
        node_types = defaultdict(int)
        for path in paths:
            for node in path.get('nodes', []):
                node_types[node.get('type', 'unknown')] += 1
        
        # Count unique source IPs
        source_ips = set(p.get('src_ip', '') for p in paths)
        
        # Count unique countries
        countries = set()
        for path in paths:
            for node in path.get('nodes', []):
                if node.get('country') and node.get('country') != 'Unknown':
                    countries.add(node.get('country'))
        
        return {
            'total_paths': total_paths,
            'complete_paths': complete_paths,
            'incomplete_paths': total_paths - complete_paths,
            'avg_path_length': round(avg_path_length, 1),
            'avg_confidence': round(avg_confidence, 3),
            'min_path_length': min(path_lengths) if path_lengths else 0,
            'max_path_length': max(path_lengths) if path_lengths else 0,
            'node_types': dict(node_types),
            'unique_sources': len(source_ips),
            'unique_countries': len(countries),
        }
    
    def _create_empty_result(self) -> Dict:
        """Create empty result structure"""
        return {
            'paths': [],
            'statistics': {},
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_paths': 0,
                'min_confidence': self.min_confidence,
                'max_path_length': self.max_path_length,
            }
        }
    
    def save_paths_to_json(self, paths_data: Dict, filename: str = None) -> str:
        """Save reconstructed paths to JSON file"""
        if not paths_data or not paths_data.get('paths'):
            print("⚠️  No paths data to save")
            return ""
        
        if filename is None:
            filename = os.path.join("data", "reconstructed_paths.json")
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, 'w') as f:
                json.dump(paths_data, f, indent=2)
            
            print(f"💾 Saved {len(paths_data['paths'])} paths to {filename}")
            return filename
            
        except Exception as e:
            print(f"❌ Error saving paths to JSON: {e}")
            return ""
    
    def load_paths_from_json(self, filename: str = None) -> Optional[Dict]:
        """Load reconstructed paths from JSON file"""
        if filename is None:
            filename = os.path.join("data", "reconstructed_paths.json")
        
        try:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    paths_data = json.load(f)
                
                print(f"📂 Loaded {len(paths_data.get('paths', []))} paths from {filename}")
                return paths_data
            else:
                print(f"⚠️  Paths file {filename} not found")
                return None
                
        except Exception as e:
            print(f"❌ Error loading paths from JSON: {e}")
            return None
    
    def get_path_by_id(self, path_id: str, paths_data: Dict) -> Optional[Dict]:
        """Get a specific path by ID"""
        if not paths_data or not paths_data.get('paths'):
            return None
        
        for path in paths_data['paths']:
            if path.get('path_id') == path_id:
                return path
        
        return None
    
    def get_paths_by_source(self, src_ip: str, paths_data: Dict) -> List[Dict]:
        """Get all paths from a specific source IP"""
        if not paths_data or not paths_data.get('paths'):
            return []
        
        return [p for p in paths_data['paths'] if p.get('src_ip') == src_ip]
    
    def get_paths_by_destination(self, dst_ip: str, paths_data: Dict) -> List[Dict]:
        """Get all paths to a specific destination IP"""
        if not paths_data or not paths_data.get('paths'):
            return []
        
        return [p for p in paths_data['paths'] if p.get('dst_ip') == dst_ip]
    
    def export_path_summary(self, paths_data: Dict) -> pd.DataFrame:
        """Export path summary to DataFrame"""
        if not paths_data or not paths_data.get('paths'):
            return pd.DataFrame()
        
        summary_data = []
        for path in paths_data['paths']:
            summary_data.append({
                'path_id': path.get('path_id', ''),
                'src_ip': path.get('src_ip', ''),
                'dst_ip': path.get('dst_ip', ''),
                'entry_node': path.get('entry_node', {}).get('ip', ''),
                'exit_node': path.get('exit_node', {}).get('ip', '') if path.get('exit_node') else '',
                'total_hops': path.get('total_hops', 0),
                'confidence': path.get('avg_confidence', 0),
                'complete': path.get('complete', False),
                'countries': ', '.join(set(
                    node.get('country', '') for node in path.get('nodes', [])
                    if node.get('country') and node.get('country') != 'Unknown'
                )),
            })
        
        return pd.DataFrame(summary_data)

# Test function
def test_path_reconstruction():
    """Test the path reconstruction module"""
    print("🧪 Testing path reconstruction module...")
    print("="*60)
    
    # Create sample data
    print("📝 Creating sample data...")
    
    # Sample correlation results
    correlation_data = []
    for i in range(10):
        correlation_data.append({
            'flow_id': f'flow_{i:04d}',
            'src_ip': f'192.168.1.{i % 3 + 1}',
            'dst_ip': f'10.0.0.{i % 2 + 1}',
            'tor_node_ip': f'185.220.101.{i % 5 + 1}',
            'tor_node_name': f'TorNode{i}',
            'total_score': 0.6 + (i * 0.04),
            'temporal_score': 0.7,
            'bandwidth_score': 0.5,
            'pattern_score': 0.6,
        })
    
    correlation_df = pd.DataFrame(correlation_data)
    
    # Sample Tor nodes
    tor_nodes_data = []
    for i in range(20):
        tor_nodes_data.append({
            'ip_address': f'185.220.101.{i + 1}',
            'nickname': f'TorNode{i}',
            'role': 'Guard' if i < 10 else ('Exit' if i < 15 else 'Relay'),
            'country_name': 'United States' if i < 10 else 'Germany',
            'observed_bandwidth_mbps': 10 + i * 5,
            'performance_score': 0.5 + (i * 0.025),
            'is_guard': 1 if i < 10 else 0,
            'is_exit': 1 if 10 <= i < 15 else 0,
        })
    
    tor_nodes_df = pd.DataFrame(tor_nodes_data)
    
    print(f"✅ Created {len(correlation_df)} sample correlations")
    print(f"✅ Created {len(tor_nodes_df)} sample Tor nodes")
    
    # Test path reconstruction
    print("\n🔄 Testing path reconstruction...")
    reconstructor = PathReconstructor(min_confidence=0.5)
    paths_data = reconstructor.reconstruct_paths(correlation_df, tor_nodes_df)
    
    if paths_data and paths_data.get('paths'):
        print(f"\n📊 PATH RECONSTRUCTION RESULTS:")
        print("-"*40)
        stats = paths_data.get('statistics', {})
        print(f"Total Paths: {stats.get('total_paths', 0)}")
        print(f"Complete Paths: {stats.get('complete_paths', 0)}")
        print(f"Average Path Length: {stats.get('avg_path_length', 0):.1f} hops")
        print(f"Average Confidence: {stats.get('avg_confidence', 0):.3f}")
        
        # Show sample path
        if paths_data['paths']:
            sample_path = paths_data['paths'][0]
            print(f"\n🔍 SAMPLE PATH DETAILS:")
            print("-"*40)
            print(f"Path ID: {sample_path.get('path_id', 'N/A')}")
            print(f"Source: {sample_path.get('src_ip', 'N/A')}")
            print(f"Destination: {sample_path.get('dst_ip', 'N/A')}")
            print(f"Confidence: {sample_path.get('avg_confidence', 0):.3f}")
            print(f"Complete: {sample_path.get('complete', False)}")
            print(f"Total Hops: {sample_path.get('total_hops', 0)}")
            
            print("\nPath Flow:")
            for i, node in enumerate(sample_path.get('nodes', [])):
                node_type = node.get('type', 'unknown')
                node_name = node.get('nickname', node.get('ip', '?'))
                print(f"  {i+1}. [{node_type.upper()}] {node_name}")
        
        # Test export functions
        print("\n💾 Testing export functions...")
        
        # Test JSON save/load
        test_json = "test_paths.json"
        reconstructor.save_paths_to_json(paths_data, test_json)
        
        if os.path.exists(test_json):
            loaded_paths = reconstructor.load_paths_from_json(test_json)
            if loaded_paths and len(loaded_paths.get('paths', [])) == len(paths_data['paths']):
                print("✅ JSON save/load test PASSED!")
            else:
                print("❌ JSON save/load test FAILED")
            
            # Clean up test file
            os.remove(test_json)
        
        # Test DataFrame export
        summary_df = reconstructor.export_path_summary(paths_data)
        if not summary_df.empty:
            print(f"✅ DataFrame export test PASSED! ({len(summary_df)} paths)")
            print("\nPath Summary:")
            print(summary_df[['src_ip', 'dst_ip', 'total_hops', 'confidence']].head())
        else:
            print("❌ DataFrame export test FAILED")
        
        print("\n✅ Path reconstruction module test PASSED!")
        return True
    else:
        print("❌ Path reconstruction module test FAILED - no paths reconstructed")
        return False

if __name__ == "__main__":
    # Run test
    test_path_reconstruction()