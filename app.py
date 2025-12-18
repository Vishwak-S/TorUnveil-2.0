
"""
app.py - TOR-Unveil Dashboard (CSV-based workflow)
Main Streamlit application using CSV files for data storage
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import json
import base64
from io import StringIO
import sys

# Import our CSV-based modules
sys.path.append('modules')
from tor_map import TorNetworkMapper
from pcap_parser import PCAPAnalyzer
from correlator import CorrelationEngine

# 🔹 NEW: import newly added modules
from path_reconstructor import PathReconstructor
from report import ForensicReportGenerator
from visualization import NetworkVisualizer

# Page configuration
st.set_page_config(
    page_title="TOR-Unveil Forensic System",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #3B82F6;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
        margin-bottom: 1rem;
    }
    .success-box {
        background-color: #D1FAE5;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #10B981;
        margin: 1rem 0;
    }
    .warning-box {
        background-color: #FEF3C7;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #F59E0B;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #E0F2FE;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #0EA5E9;
        margin: 1rem 0;
    }
    .stProgress > div > div > div > div {
        background-color: #3B82F6;
    }
    .filter-card {
        background-color: #F1F5F9;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #E2E8F0;
        margin-bottom: 1.5rem;
    }
    .filter-title {
        font-weight: 600;
        color: #475569;
        margin-bottom: 1rem;
        font-size: 1.1rem;
    }
    .csv-status {
        font-size: 0.9rem;
        color: #6B7280;
        font-family: monospace;
    }
    .network-graph {
        background-color: white;
        border-radius: 10px;
        padding: 10px;
        border: 1px solid #e2e8f0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables
def init_session_state():
    """Initialize session state variables for CSV workflow"""
    if 'tor_nodes_df' not in st.session_state:
        st.session_state.tor_nodes_df = None
    if 'flows_df' not in st.session_state:
        st.session_state.flows_df = None
    if 'correlation_results' not in st.session_state:
        st.session_state.correlation_results = None
    if 'correlation_stats' not in st.session_state:
        st.session_state.correlation_stats = {}
    if 'tor_metrics' not in st.session_state:
        st.session_state.tor_metrics = {}
    if 'flow_stats' not in st.session_state:
        st.session_state.flow_stats = {}
    if 'csv_files_ready' not in st.session_state:
        st.session_state.csv_files_ready = False
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = None
    if 'current_tab' not in st.session_state:
        st.session_state.current_tab = "Dashboard"
    if 'path_results' not in st.session_state:
        st.session_state.path_results = None
    if 'forensic_report' not in st.session_state:
        st.session_state.forensic_report = None

init_session_state()

# Helper functions
def get_table_download_link(df, filename="data.csv", text="Download CSV"):
    """Generate a link to download a dataframe as CSV"""
    csv = df.to_csv(index=False)
    b64 = base64.b64encode(csv.encode()).decode()
    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">{text}</a>'
    return href

def check_csv_files():
    """Check if CSV files exist and are valid"""
    data_dir = "data"
    files_exist = {
        'tor_nodes.csv': os.path.exists(os.path.join(data_dir, 'tor_nodes.csv')),
        'pcap_flows.csv': os.path.exists(os.path.join(data_dir, 'pcap_flows.csv')),
        'correlation_results.csv': os.path.exists(os.path.join(data_dir, 'correlation_results.csv'))
    }
    
    return files_exist

def load_csv_files():
    """Load data from CSV files"""
    data_dir = "data"
    
    # Load Tor nodes
    tor_nodes_path = os.path.join(data_dir, "tor_nodes.csv")
    if os.path.exists(tor_nodes_path):
        try:
            st.session_state.tor_nodes_df = pd.read_csv(tor_nodes_path)
            # Calculate metrics
            if not st.session_state.tor_nodes_df.empty:
                mapper = TorNetworkMapper()
                st.session_state.tor_metrics = mapper._calculate_metrics(st.session_state.tor_nodes_df)
        except Exception as e:
            st.error(f"Error loading Tor nodes CSV: {e}")
    
    # Load flows
    flows_path = os.path.join(data_dir, "pcap_flows.csv")
    if os.path.exists(flows_path):
        try:
            st.session_state.flows_df = pd.read_csv(flows_path)
            # Calculate statistics
            if not st.session_state.flows_df.empty:
                analyzer = PCAPAnalyzer()
                st.session_state.flow_stats = analyzer.get_flow_statistics(st.session_state.flows_df)
        except Exception as e:
            st.error(f"Error loading flows CSV: {e}")
    
    # Load correlation results
    results_path = os.path.join(data_dir, "correlation_results.csv")
    if os.path.exists(results_path):
        try:
            st.session_state.correlation_results = pd.read_csv(results_path)
            if not st.session_state.correlation_results.empty:
                engine = CorrelationEngine()
                st.session_state.correlation_stats = engine._calculate_correlation_stats(st.session_state.correlation_results)
        except Exception as e:
            st.error(f"Error loading correlation results: {e}")
    
    # Update status
    files_exist = check_csv_files()
    st.session_state.csv_files_ready = any(files_exist.values())

def refresh_tor_data():
    """Refresh Tor network data"""
    with st.spinner("Fetching latest Tor network data..."):
        try:
            mapper = TorNetworkMapper()
            df, metrics = mapper.get_tor_data(force_refresh=True)
            
            if not df.empty:
                st.session_state.tor_nodes_df = df
                st.session_state.tor_metrics = metrics
                st.session_state.last_refresh = datetime.now()
                return True
            else:
                st.error("Failed to fetch Tor network data")
                return False
        except Exception as e:
            st.error(f"Error: {e}")
            return False

def analyze_pcap_file(uploaded_file):
    """Analyze uploaded PCAP file"""
    with st.spinner("Analyzing PCAP file..."):
        try:
            # Save uploaded file temporarily
            temp_path = "temp_upload.pcap"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Analyze PCAP
            analyzer = PCAPAnalyzer()
            df, stats = analyzer.analyze_and_export(temp_path)
            
            if not df.empty:
                st.session_state.flows_df = df
                st.session_state.flow_stats = stats
                return True
            else:
                st.error("No flows extracted from PCAP")
                return False
        except Exception as e:
            st.error(f"Error analyzing PCAP: {e}")
            return False
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

def run_correlation():
    """Run correlation engine"""
    with st.spinner("Running correlation engine..."):
        try:
            engine = CorrelationEngine()
            
            # Load data into engine
            engine.tor_nodes_df = st.session_state.tor_nodes_df
            engine.flows_df = st.session_state.flows_df
            
            # Run correlation
            results = engine.run_correlation()
            
            if not results.empty:
                st.session_state.correlation_results = results
                st.session_state.correlation_stats = engine.correlation_stats
                return True
            else:
                st.warning("No correlations found")
                return False
        except Exception as e:
            st.error(f"Error running correlation: {e}")
            return False

def reset_all_data():
    """Reset all session data"""
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    init_session_state()
    
    # Clear CSV files
    data_dir = "data"
    csv_files = ['tor_nodes.csv', 'pcap_flows.csv', 'correlation_results.csv']
    for file in csv_files:
        file_path = os.path.join(data_dir, file)
        if os.path.exists(file_path):
            os.remove(file_path)

# Main dashboard
def main():
    """Main dashboard application"""
    
    # Header
    st.markdown('<h1 class="main-header">🔍 TOR-Unveil Forensic System</h1>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-box">
    <strong style='color:black;'>CSV-Based Workflow:</strong> 
    <p style='color:black;'>A forensic pipeline that correlates network captures with Tor nodes using CSV files for data storage.
    All data is saved to CSV files in the 'data' directory for persistence and analysis.</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check and load CSV files on startup
    if not st.session_state.csv_files_ready:
        load_csv_files()
    
    # Sidebar
    with st.sidebar:
        st.markdown("## ⚙️ Configuration")
        
        # CSV Status
        st.markdown("### 📁 CSV File Status")
        files_exist = check_csv_files()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Tor Data", 
                     "✅" if files_exist['tor_nodes.csv'] else "❌",
                     "CSV Ready" if files_exist['tor_nodes.csv'] else "Missing")
        
        with col2:
            st.metric("Flow Data", 
                     "✅" if files_exist['pcap_flows.csv'] else "❌",
                     "CSV Ready" if files_exist['pcap_flows.csv'] else "Missing")
        
        with col3:
            st.metric("Results", 
                     "✅" if files_exist['correlation_results.csv'] else "❌",
                     "CSV Ready" if files_exist['correlation_results.csv'] else "Missing")
        
        # Data Management
        st.markdown("### 🔄 Data Management")
        
        # Tor Network Data
        if st.button("🔄 Refresh Tor Data", use_container_width=True):
            if refresh_tor_data():
                st.success(f"Loaded {len(st.session_state.tor_nodes_df)} Tor nodes")
                st.rerun()
        
        # PCAP Upload
        st.markdown("### 📁 PCAP Analysis")
        uploaded_file = st.file_uploader(
            "Upload network capture",
            type=['pcap', 'pcapng', 'cap'],
            help="Upload a PCAP/PCAPNG file for analysis"
        )
        
        if uploaded_file is not None:
            if st.button("🔍 Analyze PCAP", use_container_width=True):
                if analyze_pcap_file(uploaded_file):
                    st.success(f"Analyzed {len(st.session_state.flows_df)} flows")
                    st.rerun()
        
        # Data Pipeline
        st.markdown("### ⚡ Quick Pipeline")
        if st.button("▶️ Run Complete Pipeline", use_container_width=True):
            progress_bar = st.progress(0)
            
            # Step 1: Tor Data
            progress_bar.progress(25)
            if refresh_tor_data():
                # Step 2: Use existing or sample flows
                progress_bar.progress(50)
                if st.session_state.flows_df is None:
                    # Create sample flows if none exist
                    analyzer = PCAPAnalyzer()
                    st.session_state.flows_df = analyzer._create_sample_flows()
                
                # Step 3: Correlation
                progress_bar.progress(75)
                if run_correlation():
                    progress_bar.progress(100)
                    st.success("Pipeline completed successfully!")
                    st.rerun()
                else:
                    progress_bar.progress(100)
                    st.error("Correlation failed")
            else:
                progress_bar.progress(100)
                st.error("Failed to fetch Tor data")
        
        # Reset button
        st.markdown("---")
        if st.button("🗑️ Reset All Data", use_container_width=True):
            reset_all_data()
            st.success("All data reset")
            st.rerun()
        
        # Last refresh time
        if st.session_state.last_refresh:
            st.caption(f"Last refresh: {st.session_state.last_refresh.strftime('%H:%M:%S')}")
        
        # Status indicators
        st.markdown("### 📊 Current Status")
        col1, col2 = st.columns(2)
        with col1:
            tor_count = len(st.session_state.tor_nodes_df) if st.session_state.tor_nodes_df is not None else 0
            st.metric("Tor Nodes", tor_count)
        
        with col2:
            flow_count = len(st.session_state.flows_df) if st.session_state.flows_df is not None else 0
            st.metric("Flows", flow_count)
    
    # Main content area - FIXED: All 7 tabs are properly defined
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📈 Dashboard", 
        "🌐 Tor Network", 
        "📊 PCAP Analysis", 
        "🔗 Correlation Results",
        "🛣️ Path Reconstruction",
        "📋 Forensic Report",
        "🕸️ Network Visualization"
    ])
    
    # Tab 1: Dashboard
    with tab1:
        st.markdown('<h2 class="sub-header">System Overview</h2>', unsafe_allow_html=True)
        
        # Overview metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Tor Network Size",
                f"{st.session_state.tor_metrics.get('total_relays', 0):,}",
                f"{st.session_state.tor_metrics.get('guard_count', 0)} Guards"
            )
        
        with col2:
            st.metric(
                "Network Bandwidth",
                f"{st.session_state.tor_metrics.get('total_bandwidth_gbps', 0):.1f} Gbps",
                f"{st.session_state.tor_metrics.get('country_count', 0)} Countries"
            )
        
        with col3:
            st.metric(
                "PCAP Analysis",
                f"{st.session_state.flow_stats.get('total_flows', 0):,}",
                f"{st.session_state.flow_stats.get('suspected_tor_flows', 0)} Tor-like"
            )
        
        with col4:
            avg_score = st.session_state.correlation_stats.get('avg_total_score', 0)
            confidence = "🟢 High" if avg_score >= 0.7 else "🟡 Medium" if avg_score >= 0.5 else "🔴 Low"
            st.metric(
                "Avg Correlation",
                f"{avg_score:.3f}",
                confidence
            )
        
        # CSV File Status
        st.markdown("### 📁 CSV File Status")
        files_exist = check_csv_files()
        
        status_col1, status_col2, status_col3 = st.columns(3)
        
        with status_col1:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>Tor Nodes CSV</h4>
            <p style='color:black;' class="csv-status">data/tor_nodes.csv</p>
            <p style='color:black;'>Status: <strong>{}</strong></p>
            <p style='color:black;'>Records: {}</p>
            </div>
            """.format(
                "✅ Available" if files_exist['tor_nodes.csv'] else "❌ Missing",
                len(st.session_state.tor_nodes_df) if st.session_state.tor_nodes_df is not None else 0
            ), unsafe_allow_html=True)
        
        with status_col2:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>PCAP Flows CSV</h4>
            <p style='color:black;' class="csv-status">data/pcap_flows.csv</p>
            <p style='color:black;'>Status: <strong>{}</strong></p>
            <p style='color:black;'>Records: {}</p>
            </div>
            """.format(
                "✅ Available" if files_exist['pcap_flows.csv'] else "❌ Missing",
                len(st.session_state.flows_df) if st.session_state.flows_df is not None else 0
            ), unsafe_allow_html=True)
        
        with status_col3:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>Correlation CSV</h4>
            <p style='color:black;' class="csv-status">data/correlation_results.csv</p>
            <p style='color:black;'>Status: <strong>{}</strong></p>
            <p style='color:black;'>Records: {}</p>
            </div>
            """.format(
                "✅ Available" if files_exist['correlation_results.csv'] else "❌ Missing",
                len(st.session_state.correlation_results) if st.session_state.correlation_results is not None else 0
            ), unsafe_allow_html=True)
        
        # Download all data
        st.markdown("### 📥 Download Data")
        download_col1, download_col2, download_col3 = st.columns(3)
        
        with download_col1:
            if st.session_state.tor_nodes_df is not None and not st.session_state.tor_nodes_df.empty:
                st.markdown(get_table_download_link(
                    st.session_state.tor_nodes_df,
                    filename="tor_nodes.csv",
                    text="📥 Download Tor Nodes CSV"
                ), unsafe_allow_html=True)
        
        with download_col2:
            if st.session_state.flows_df is not None and not st.session_state.flows_df.empty:
                st.markdown(get_table_download_link(
                    st.session_state.flows_df,
                    filename="pcap_flows.csv",
                    text="📥 Download Flows CSV"
                ), unsafe_allow_html=True)
        
        with download_col3:
            if st.session_state.correlation_results is not None and not st.session_state.correlation_results.empty:
                st.markdown(get_table_download_link(
                    st.session_state.correlation_results,
                    filename="correlation_results.csv",
                    text="📥 Download Results CSV"
                ), unsafe_allow_html=True)
        
        # Quick start guide
        st.markdown("### 🚀 CSV-Based Workflow")
        guide_col1, guide_col2, guide_col3 = st.columns(3)
        
        with guide_col1:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>1. Load/Refresh Data</h4>
            <p style='color:black;'>Click "Refresh Tor Data" to fetch current Tor nodes. 
            All data is saved to CSV files in the 'data' directory.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with guide_col2:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>2. Analyze PCAP</h4>
            <p style='color:black;'>Upload a PCAP file or use existing flow data. 
            Flow data is saved to pcap_flows.csv for persistent storage.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with guide_col3:
            st.markdown("""
            <div class="metric-card">
            <h4 style='color:black;'>3. Run Correlation</h4>
            <p style='color:black;'>Click "Run Correlation" to analyze matches between flows and Tor nodes.
            Results are saved to correlation_results.csv.</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Tab 2: Tor Network
    with tab2:
        st.markdown('<h2 class="sub-header">Tor Network Analysis</h2>', unsafe_allow_html=True)
        
        if st.session_state.tor_nodes_df is None or st.session_state.tor_nodes_df.empty:
            st.info("👈 Click 'Refresh Tor Data' in the sidebar to load Tor network data")
        else:
            # Tor data visualization
            st.markdown("### 📊 Tor Network Visualization")
            
            # Create visualization tabs
            viz_tab1, viz_tab2, viz_tab3 = st.tabs(["Geographic", "Role Distribution", "Performance"])
            
            with viz_tab1:
                if 'country_name' in st.session_state.tor_nodes_df.columns:
                    country_counts = st.session_state.tor_nodes_df['country_name'].value_counts().reset_index()
                    country_counts.columns = ['Country', 'Node Count']
                    
                    fig = px.bar(
                        country_counts.head(10),
                        x='Country',
                        y='Node Count',
                        title="Top 10 Countries by Tor Node Count",
                        color='Node Count',
                        color_continuous_scale='Blues'
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with viz_tab2:
                if 'role' in st.session_state.tor_nodes_df.columns:
                    role_counts = st.session_state.tor_nodes_df['role'].value_counts().reset_index()
                    role_counts.columns = ['Role', 'Count']
                    
                    fig = px.pie(
                        role_counts,
                        values='Count',
                        names='Role',
                        title="Tor Node Role Distribution",
                        hole=0.3
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with viz_tab3:
                if 'observed_bandwidth_mbps' in st.session_state.tor_nodes_df.columns:
                    fig = px.histogram(
                        st.session_state.tor_nodes_df,
                        x='observed_bandwidth_mbps',
                        nbins=20,
                        title="Tor Node Bandwidth Distribution (Mbps)",
                        labels={'observed_bandwidth_mbps': 'Bandwidth (Mbps)'},
                        color_discrete_sequence=['#3B82F6']
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            # Tor data table
            st.markdown("### 📋 Tor Node Details")
            
            # Display table with pagination
            display_df = st.session_state.tor_nodes_df.copy()
            
            # Select columns for display
            display_cols = ['nickname', 'ip_address', 'role', 'country_name', 
                          'observed_bandwidth_mbps', 'uptime_days']
            
            available_cols = [col for col in display_cols if col in display_df.columns]
            
            if available_cols:
                display_df = display_df[available_cols].head(100)  # Limit display
                
                st.dataframe(
                    display_df.rename(columns={
                        'nickname': 'Name',
                        'ip_address': 'IP Address',
                        'role': 'Role',
                        'country_name': 'Country',
                        'observed_bandwidth_mbps': "Bandwidth (Mbps)",
                        'uptime_days': 'Uptime (Days)'
                    }),
                    use_container_width=True,
                    height=400
                )
    
    # Tab 3: PCAP Analysis
    with tab3:
        st.markdown('<h2 class="sub-header">PCAP Flow Analysis</h2>', unsafe_allow_html=True)
        
        if st.session_state.flows_df is None or st.session_state.flows_df.empty:
            st.info("👈 Upload a PCAP file and click 'Analyze PCAP' to begin analysis")
        else:
            # Flow statistics
            st.markdown("### 📊 Flow Statistics")
            
            stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
            
            with stats_col1:
                st.metric("Total Flows", st.session_state.flow_stats.get('total_flows', 0))
            
            with stats_col2:
                st.metric("Suspected Tor", st.session_state.flow_stats.get('suspected_tor_flows', 0))
            
            with stats_col3:
                st.metric("Total Packets", st.session_state.flow_stats.get('total_packets', 0))
            
            with stats_col4:
                st.metric("Total Data", f"{st.session_state.flow_stats.get('total_bytes', 0) / 1_000_000:.1f} MB")
            
            # Time range
            if 'time_range' in st.session_state.flow_stats:
                time_range = st.session_state.flow_stats['time_range']
                st.markdown(f"**Capture Time Range:** {time_range.get('start', 'N/A')} to {time_range.get('end', 'N/A')}")
            
            # Flow visualizations
            st.markdown("### 📈 Flow Analysis")
            
            if not st.session_state.flows_df.empty:
                viz_col1, viz_col2 = st.columns(2)
                
                with viz_col1:
                    # Port distribution
                    if 'dst_port' in st.session_state.flows_df.columns:
                        port_counts = st.session_state.flows_df['dst_port'].value_counts().head(10).reset_index()
                        port_counts.columns = ['Port', 'Count']
                        
                        fig = px.bar(
                            port_counts,
                            x='Port',
                            y='Count',
                            title="Top 10 Destination Ports",
                            color='Count',
                            color_continuous_scale='Viridis'
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                with viz_col2:
                    # Tor confidence distribution
                    if 'tor_confidence' in st.session_state.flows_df.columns:
                        fig = px.histogram(
                            st.session_state.flows_df,
                            x='tor_confidence',
                            nbins=20,
                            title="Tor Confidence Score Distribution",
                            labels={'tor_confidence': 'Tor Confidence Score'},
                            color_discrete_sequence=['#10B981']
                        )
                        st.plotly_chart(fig, use_container_width=True)
            
            # Flow table
            st.markdown("### 📋 Detected Flows")
            
            # Display table with pagination
            display_df = st.session_state.flows_df.copy()
            
            # Select columns for display
            flow_display_cols = ['flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 
                              'protocol', 'packet_count', 'total_bytes', 'duration_seconds',
                              'tor_confidence', 'is_suspected_tor']
            
            available_flow_cols = [col for col in flow_display_cols if col in display_df.columns]
            
            if available_flow_cols:
                display_df = display_df[available_flow_cols].head(100)  # Limit display
                
                # Format columns
                if 'tor_confidence' in display_df.columns:
                    display_df['tor_confidence'] = display_df['tor_confidence'].apply(lambda x: f"{x:.3f}")
                
                if 'is_suspected_tor' in display_df.columns:
                    display_df['is_suspected_tor'] = display_df['is_suspected_tor'].apply(
                        lambda x: '✅ Yes' if x == 1 else '❌ No'
                    )
                
                st.dataframe(
                    display_df.rename(columns={
                        'flow_id': 'Flow ID',
                        'src_ip': 'Source IP',
                        'src_port': 'Source Port',
                        'dst_ip': 'Destination IP',
                        'dst_port': 'Destination Port',
                        'protocol': 'Protocol',
                        'packet_count': 'Packets',
                        'total_bytes': 'Bytes',
                        'duration_seconds': 'Duration (s)',
                        'tor_confidence': 'Tor Confidence',
                        'is_suspected_tor': 'Suspected Tor'
                    }),
                    use_container_width=True,
                    height=400
                )
    
    # Tab 4: Correlation Results
    with tab4:
        st.markdown('<h2 class="sub-header">Correlation Analysis</h2>', unsafe_allow_html=True)
        
        if st.session_state.correlation_results is None or st.session_state.correlation_results.empty:
            st.info("👈 Run correlation analysis to see results")
        else:
            # Correlation statistics
            st.markdown("### 📊 Correlation Statistics")
            
            stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
            
            with stats_col1:
                high_conf = st.session_state.correlation_stats.get('high_confidence', 0)
                st.metric("High Confidence", high_conf)
            
            with stats_col2:
                total_corr = st.session_state.correlation_stats.get('total_correlations', 0)
                st.metric("Total Correlations", total_corr)
            
            with stats_col3:
                avg_score = st.session_state.correlation_stats.get('avg_total_score', 0)
                st.metric("Average Score", f"{avg_score:.3f}")
            
            with stats_col4:
                unique_nodes = st.session_state.correlation_stats.get('unique_tor_nodes', 0)
                st.metric("Unique Nodes", unique_nodes)
            
            # Score distribution
            st.markdown("### 📈 Score Distribution")
            
            if 'score_distribution' in st.session_state.correlation_stats:
                score_dist = st.session_state.correlation_stats['score_distribution']
                score_df = pd.DataFrame(list(score_dist.items()), columns=['Score Range', 'Count'])
                
                fig = px.bar(
                    score_df,
                    x='Score Range',
                    y='Count',
                    title="Correlation Score Distribution",
                    color='Count',
                    color_continuous_scale='RdYlGn'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Correlation table
            st.markdown("### 📋 Correlation Results")
            
            results_df = st.session_state.correlation_results
            
            # Add confidence badges if not present
            if 'confidence_badge' not in results_df.columns and 'total_score' in results_df.columns:
                def get_badge(score):
                    if score >= 0.8: return "🟢 HIGH"
                    elif score >= 0.6: return "🟡 MEDIUM"
                    elif score >= 0.4: return "🟠 LOW"
                    else: return "🔴 WEAK"
                
                results_df['confidence_badge'] = results_df['total_score'].apply(get_badge)
            
            # Display table with filters
            filter_col1, filter_col2 = st.columns(2)
            
            with filter_col1:
                min_score = st.slider(
                    "Minimum Score",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.0,
                    step=0.1
                )
            
            with filter_col2:
                confidence_filter = st.multiselect(
                    "Confidence Level",
                    options=['🟢 HIGH', '🟡 MEDIUM', '🟠 LOW', '🔴 WEAK'],
                    default=['🟢 HIGH', '🟡 MEDIUM']
                )
            
            # Apply filters
            filtered_results = results_df[results_df['total_score'] >= min_score].copy()
            
            if confidence_filter:
                filtered_results = filtered_results[filtered_results['confidence_badge'].isin(confidence_filter)]
            
            # Display table
            display_cols = [
                'confidence_badge', 'tor_node_name', 'tor_node_ip', 'tor_node_country',
                'src_ip', 'dst_ip', 'total_score', 'temporal_score', 'bandwidth_score', 
                'pattern_score'
            ]
            
            available_cols = [col for col in display_cols if col in filtered_results.columns]
            
            if available_cols:
                st.dataframe(
                    filtered_results[available_cols].rename(columns={
                        'confidence_badge': 'Confidence',
                        'tor_node_name': 'Node Name',
                        'tor_node_ip': 'Node IP',
                        'tor_node_country': 'Node Country',
                        'src_ip': 'Source IP',
                        'dst_ip': 'Dest IP',
                        'total_score': 'Total Score',
                        'temporal_score': 'Temporal',
                        'bandwidth_score': 'Bandwidth',
                        'pattern_score': 'Pattern'
                    }),
                    use_container_width=True,
                    height=400
                )
            
            # Generate forensic report
            st.markdown("### 📄 Forensic Report")
            
            if st.button("Generate Forensic Report", key="gen_report_tab4"):
                engine = CorrelationEngine()
                
                report_threshold = 0.6
                report_df = filtered_results[
                    filtered_results["total_score"] >= report_threshold
                ].copy()
                
                engine.results = report_df.to_dict("records")
                engine.correlation_stats = st.session_state.correlation_stats
                
                report = engine.generate_forensic_report()
                
                st.subheader("Forensic Correlation Summary")
                
                st.markdown(f"""
                **Total Correlations:** {len(report_df)}  
                **High Confidence Matches:** {len(report_df[report_df['total_score'] >= 0.8])}  
                **Average Correlation Score:** {report_df['total_score'].mean():.2f}
                """)
                
                st.markdown("### 🧾 Correlation Attribute Analysis")
                
                report_df["Suspected Tor"] = report_df["total_score"].apply(
                    lambda x: "YES" if x >= 0.6 else "NO"
                )
                
                report_df["Confidence Level"] = report_df["total_score"].apply(
                    lambda x: "HIGH" if x >= 0.8 else "MEDIUM" if x >= 0.6 else "LOW"
                )
                
                report_df["Evidence Strength"] = report_df["total_score"].apply(
                    lambda x: "Strong multi-factor correlation"
                    if x >= 0.8 else
                    "Moderate Tor-like behavior"
                    if x >= 0.6 else
                    "Weak or inconclusive"
                )
                
                st.dataframe(
                    report_df[[
                        "Suspected Tor",
                        "Confidence Level",
                        "tor_node_name",
                        "tor_node_ip",
                        "tor_node_country",
                        "src_ip",
                        "dst_ip",
                        "total_score",
                        "Evidence Strength"
                    ]],
                    use_container_width=True,
                    height=320
                )
                
                st.markdown("### 📄 Detailed Forensic Report")
                st.text_area("Report Content", report, height=350)
    
    # Tab 5: Path Reconstruction
    with tab5:
        st.markdown('<h2 class="sub-header">Network Path Reconstruction</h2>', unsafe_allow_html=True)
        
        if st.session_state.correlation_results is None or st.session_state.correlation_results.empty:
            st.info("👈 Run correlation analysis first to reconstruct paths")
        else:
            st.markdown("### 🛣️ Path Reconstruction Configuration")
            
            col1, col2 = st.columns(2)
            with col1:
                min_confidence = st.slider(
                    "Minimum Confidence",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.4,
                    step=0.1
                )
            
            with col2:
                max_path_length = st.slider(
                    "Maximum Path Length",
                    min_value=2,
                    max_value=10,
                    value=6,
                    step=1
                )
            
            if st.button("🔄 Reconstruct Paths", key="reconstruct_paths_btn"):
                with st.spinner("Reconstructing network paths..."):
                    try:
                        reconstructor = PathReconstructor(
                            max_path_length=max_path_length,
                            min_confidence=min_confidence
                        )
                        
                        # Run diagnostics first
                        st.markdown("### 🔍 Diagnostics")
                        with st.expander("Click to see detailed diagnostics", expanded=True):
                            diagnosis = reconstructor.diagnose_reconstruction_issues(
                                st.session_state.correlation_results,
                                st.session_state.tor_nodes_df
                            )
                            
                            # Display diagnostic metrics
                            diag_col1, diag_col2, diag_col3, diag_col4 = st.columns(4)
                            
                            with diag_col1:
                                st.metric(
                                    "Total Correlations",
                                    diagnosis['total_correlations'],
                                    delta=f"{diagnosis['correlations_above_threshold']} above threshold"
                                )
                            
                            with diag_col2:
                                st.metric(
                                    "Potential Paths",
                                    diagnosis['potential_paths'],
                                    delta=f"Can reconstruct"
                                )
                            
                            with diag_col3:
                                st.metric(
                                    "Data Issues Found",
                                    len(diagnosis['issues_found']),
                                    delta=f"{diagnosis['tor_node_not_in_database']} not in DB"
                                )
                            
                            with diag_col4:
                                st.metric(
                                    "Reconstruction Readiness",
                                    f"{int((diagnosis['potential_paths'] / max(diagnosis['correlations_above_threshold'], 1)) * 100)}%",
                                    delta="of above-threshold correlations"
                                )
                            
                            # Visual representation of issues
                            if diagnosis['issues_found']:
                                st.warning("⚠️ **Issues Found:**")
                                for issue in diagnosis['issues_found']:
                                    st.write(f"• {issue}")
                            else:
                                st.success("✅ No issues found! Ready to reconstruct paths.")
                        
                        # Now reconstruct paths
                        st.markdown("### 🔄 Reconstructing Paths...")
                        path_results = reconstructor.reconstruct_paths(
                            st.session_state.correlation_results,
                            st.session_state.tor_nodes_df
                        )
                        
                        st.session_state.path_results = path_results
                        st.success("✅ Path reconstruction completed!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error reconstructing paths: {e}")
                        import traceback
                        st.error(traceback.format_exc())
            
            if 'path_results' in st.session_state and st.session_state.path_results:
                path_results = st.session_state.path_results
                
                st.markdown("### 📊 Path Statistics")
                
                stats = path_results.get('statistics', {})
                stats_col1, stats_col2, stats_col3, stats_col4 = st.columns(4)
                
                with stats_col1:
                    st.metric("Total Paths", stats.get('total_paths', 0))
                
                with stats_col2:
                    st.metric("Complete Paths", stats.get('complete_paths', 0))
                
                with stats_col3:
                    avg_len = stats.get('avg_path_length', 0)
                    st.metric("Avg Path Length", f"{avg_len:.1f}" if avg_len > 0 else "N/A")
                
                with stats_col4:
                    high_conf = stats.get('high_confidence_paths', 0)
                    st.metric("High Confidence", high_conf)
                
                # Path details
                st.markdown("### 🛣️ Reconstructed Paths")
                
                paths = path_results.get('paths', [])
                if paths:
                    # Create path dataframe for display
                    path_display_data = []
                    for i, path in enumerate(paths):
                        # Use correct field names
                        source_ip = path.get('source_ip', path.get('src_ip', 'N/A'))
                        dest_ip = path.get('destination_ip', path.get('dst_ip', 'N/A'))
                        confidence = path.get('confidence_score', path.get('avg_confidence', 0))
                        
                        path_display_data.append({
                            'Path ID': i + 1,
                            'Source IP': source_ip if source_ip and source_ip != 'N/A' else 'Unknown',
                            'Destination IP': dest_ip if dest_ip and dest_ip != 'N/A' else 'Unknown',
                            'Hops': path.get('hop_count', len(path.get('nodes', []))),
                            'Confidence': f"{confidence:.3f}" if confidence > 0 else "0.000",
                            'Nodes': len(path.get('nodes', [])),
                            'Complete': '✅' if path.get('complete', False) else '❌'
                        })
                    
                    path_df = pd.DataFrame(path_display_data)
                    
                    # Display the table with better formatting
                    if not path_df.empty:
                        st.dataframe(
                            path_df,
                            use_container_width=True,
                            height=400,
                            column_config={
                                "Path ID": st.column_config.NumberColumn(width="small"),
                                "Source IP": st.column_config.TextColumn(width="medium"),
                                "Destination IP": st.column_config.TextColumn(width="medium"),
                                "Hops": st.column_config.NumberColumn(width="small"),
                                "Confidence": st.column_config.ProgressColumn(
                                    min_value=0,
                                    max_value=1,
                                    format="%.3f"
                                ),
                                "Nodes": st.column_config.NumberColumn(width="small"),
                                "Complete": st.column_config.TextColumn(width="small")
                            }
                        )
                    else:
                        st.warning("No valid paths to display")
                    
                    # Detailed path view
                    st.markdown("### 📋 Detailed Path Information")
                    
                    if len(paths) > 0:
                        # Create a dropdown with meaningful labels
                        path_options = []
                        for i, path in enumerate(paths):
                            source = path.get('source_ip', path.get('src_ip', 'Unknown'))
                            dest = path.get('destination_ip', path.get('dst_ip', 'Unknown'))
                            conf = path.get('confidence_score', path.get('avg_confidence', 0))
                            label = f"Path {i+1}: {source} → {dest} (Confidence: {conf:.3f})"
                            path_options.append(label)
                        
                        selected_path_label = st.selectbox(
                            "Select a path to view details",
                            path_options,
                            index=0
                        )
                        
                        selected_path_idx = path_options.index(selected_path_label)
                        selected_path = paths[selected_path_idx]
                        
                        # Display path details
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Path ID:** {selected_path.get('path_id', 'N/A')}")
                            st.write(f"**Source IP:** {selected_path.get('source_ip', selected_path.get('src_ip', 'N/A'))}")
                            st.write(f"**Destination IP:** {selected_path.get('destination_ip', selected_path.get('dst_ip', 'N/A'))}")
                            st.write(f"**Confidence Score:** {selected_path.get('confidence_score', selected_path.get('avg_confidence', 0)):.3f}")
                        
                        with col2:
                            st.write(f"**Hop Count:** {selected_path.get('hop_count', 0)}")
                            st.write(f"**Number of Nodes:** {len(selected_path.get('nodes', []))}")
                            st.write(f"**Path Type:** {selected_path.get('path_type', 'Tor Circuit')}")
                            st.write(f"**Complete:** {'Yes' if selected_path.get('complete', False) else 'No'}")
                        
                        # Path nodes table
                        nodes = selected_path.get('nodes', [])
                        if nodes:
                            node_data = []
                            for j, node in enumerate(nodes):
                                node_data.append({
                                    'Hop': j + 1,
                                    'Type': node.get('type', 'Unknown').title(),
                                    'IP': node.get('ip', 'N/A'),
                                    'Label': node.get('label', node.get('nickname', 'N/A')),
                                    'Country': node.get('country', 'N/A'),
                                    'Bandwidth (Mbps)': node.get('bandwidth_mbps', 0),
                                    'Confidence': f"{node.get('confidence', 0):.3f}" if node.get('confidence', 0) > 0 else 'N/A'
                                })
                            
                            nodes_df = pd.DataFrame(node_data)
                            st.dataframe(nodes_df, use_container_width=True)
                            
                            # Visual representation of the path
                            st.markdown("#### 🔄 Path Flow Visualization")
                            path_flow = " → ".join([f"{node.get('type', 'Node').title()}" for node in nodes])
                            st.code(path_flow, language='text')
                        else:
                            st.info("No node details available for this path")
                else:
                    st.warning("No paths reconstructed. Try adjusting the confidence threshold.")
    
    # Tab 6: Forensic Report
    with tab6:
        st.markdown('<h2 class="sub-header">Comprehensive Forensic Report</h2>', unsafe_allow_html=True)
        
        if st.session_state.tor_nodes_df is None or st.session_state.correlation_results is None:
            st.info("👈 Complete the analysis pipeline to generate forensic reports")
        else:
            st.markdown("### 📄 Report Generation")
            
            report_col1, report_col2 = st.columns(2)
            
            with report_col1:
                report_title = st.text_input(
                    "Report Title",
                    value="TOR-Unveil Forensic Report"
                )
            
            with report_col2:
                case_reference = st.text_input(
                    "Case Reference ID",
                    value="CASE-2024-001"
                )
            
            if st.button("📋 Generate Full Forensic Report", key="gen_report_btn"):
                with st.spinner("Generating comprehensive forensic report..."):
                    try:
                        report_gen = ForensicReportGenerator(report_title=report_title)
                        
                        # Prepare flows data
                        flows_list = []
                        if st.session_state.flows_df is not None and not st.session_state.flows_df.empty:
                            flows_list = st.session_state.flows_df.to_dict('records')
                        
                        # Prepare path data
                        paths_data = st.session_state.path_results if 'path_results' in st.session_state else {}
                        
                        # Generate report
                        full_report = report_gen.generate_report(
                            tor_nodes=st.session_state.tor_nodes_df,
                            flows=flows_list,
                            correlations=st.session_state.correlation_results,
                            paths=paths_data,
                            stats={
                                'tor_metrics': st.session_state.tor_metrics,
                                'flow_stats': st.session_state.flow_stats,
                                'correlation_stats': st.session_state.correlation_stats
                            }
                        )
                        
                        st.session_state.forensic_report = full_report
                        st.success("✅ Forensic report generated!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error generating report: {e}")
            
            # In Tab 6: Forensic Report section, update the download section:

            if 'forensic_report' in st.session_state and st.session_state.forensic_report:
                report_content = st.session_state.forensic_report
                
                st.markdown("### 📊 Report Summary")
                
                # Report metrics
                report_metrics_col1, report_metrics_col2, report_metrics_col3 = st.columns(3)
                
                with report_metrics_col1:
                    tor_count = len(st.session_state.tor_nodes_df) if st.session_state.tor_nodes_df is not None else 0
                    st.metric("Tor Nodes Analyzed", tor_count)
                
                with report_metrics_col2:
                    flow_count = len(st.session_state.flows_df) if st.session_state.flows_df is not None else 0
                    st.metric("Network Flows", flow_count)
                
                with report_metrics_col3:
                    corr_count = len(st.session_state.correlation_results) if st.session_state.correlation_results is not None else 0
                    st.metric("Correlations", corr_count)
                
                # Report content tabs
                report_tab1, report_tab2, report_tab3 = st.tabs(["Full Report", "Executive Summary", "Download"])
                
                with report_tab1:
                    st.markdown("### 📄 Full Report")
                    st.text_area(
                        "Complete Forensic Report",
                        value=report_content if report_content else "No report generated yet",
                        height=500,
                        disabled=True
                    )
                
                with report_tab2:
                    st.markdown("### 📋 Executive Summary")
                    
                    summary_text = f"""
            **Case Reference:** {case_reference}
            **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            **Report Title:** {report_title}

            **Analysis Summary:**
            - Total Tor Nodes: {len(st.session_state.tor_nodes_df) if st.session_state.tor_nodes_df is not None else 0}
            - Network Flows Analyzed: {len(st.session_state.flows_df) if st.session_state.flows_df is not None else 0}
            - Correlation Results: {len(st.session_state.correlation_results) if st.session_state.correlation_results is not None else 0}
            - Average Correlation Score: {st.session_state.correlation_stats.get('avg_total_score', 0):.3f}
            - High Confidence Matches: {st.session_state.correlation_stats.get('high_confidence', 0)}

            **Findings:**
            This forensic report documents the analysis of network traffic against the Tor network database.
            The correlation engine has identified potential Tor usage patterns in the captured traffic.
                    """
                    
                    st.markdown(summary_text)
                
                with report_tab3:
                    st.markdown("### 📥 Download Report")
                    
                    download_col1, download_col2, download_col3 = st.columns(3)
                    
                    # Download as text - FIXED: Check if report_content exists
                    with download_col1:
                        if report_content:
                            report_bytes = report_content.encode('utf-8')
                            st.download_button(
                                label="📄 TXT Format",
                                data=report_bytes,
                                file_name=f"{case_reference}_forensic_report.txt",
                                mime="text/plain",
                                use_container_width=True
                            )
                        else:
                            st.warning("No report to download")
                    
                    # Download as PDF
                    with download_col2:
                        if report_content and st.button("📕 Generate PDF", key="gen_pdf_btn", use_container_width=True):
                            with st.spinner("Generating PDF..."):
                                try:
                                    report_gen = ForensicReportGenerator(report_title=report_title)
                                    pdf_file = report_gen.export_to_pdf(
                                        report_content,
                                        filename=f"data/reports/{case_reference}_forensic_report.pdf"
                                    )
                                    
                                    # Read and offer for download
                                    if pdf_file and os.path.exists(pdf_file):
                                        with open(pdf_file, 'rb') as f:
                                            pdf_bytes = f.read()
                                        
                                        st.download_button(
                                            label="📥 Download PDF",
                                            data=pdf_bytes,
                                            file_name=f"{case_reference}_forensic_report.pdf",
                                            mime="application/pdf",
                                            use_container_width=True
                                        )
                                        st.success("✅ PDF generated successfully!")
                                    else:
                                        st.error("Failed to generate PDF file")
                                except Exception as e:
                                    st.error(f"Error generating PDF: {e}")
                        elif not report_content:
                            st.info("Generate a report first")
                    
                    # Download correlation results CSV
                    with download_col3:
                        if st.session_state.correlation_results is not None and not st.session_state.correlation_results.empty:
                            csv_data = st.session_state.correlation_results.to_csv(index=False)
                            st.download_button(
                                label="📊 Correlations (CSV)",
                                data=csv_data,
                                file_name=f"{case_reference}_correlations.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
                    
                    # Export both formats at once
                    st.markdown("---")
                    st.markdown("### 📦 Export All Formats")
                    
                    if report_content and st.button("Export Both TXT + PDF", key="export_both_btn", use_container_width=True):
                        with st.spinner("Exporting both formats..."):
                            try:
                                report_gen = ForensicReportGenerator(report_title=report_title)
                                results = report_gen.export_report(
                                    report_content,
                                    output_format='both',
                                    base_filename=case_reference
                                )
                                
                                st.success("✅ Both formats exported successfully!")
                                if results.get('txt'):
                                    st.info(f"Text file: {results['txt']}")
                                if results.get('pdf'):
                                    st.info(f"PDF file: {results['pdf']}")
                            except Exception as e:
                                st.error(f"Error exporting: {e}")
            else:
                st.info("👈 Generate a forensic report first")   
    # Tab 7: Network Visualization - FIXED: Now properly visible
    with tab7:
        st.markdown('<h2 class="sub-header">Network Graph Visualization</h2>', unsafe_allow_html=True)
        
        if st.session_state.correlation_results is None or st.session_state.correlation_results.empty:
            st.info("👈 Run correlation analysis to visualize network graphs")
        else:
            st.markdown("### 🕸️ Network Visualization")
            
            # Visualization options
            viz_col1, viz_col2 = st.columns(2)
            
            with viz_col1:
                visualization_type = st.selectbox(
                    "Visualization Type",
                    ["Simple Network Graph", "Compact IP Diagram", "Tor Node Network", "Path Hops"]
                )
            
            with viz_col2:
                min_score_filter = st.slider(
                    "Minimum Correlation Score",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.5,
                    step=0.1
                )
            
            if st.button("🎨 Generate Visualization", key="gen_viz_btn"):
                with st.spinner("Generating network visualization..."):
                    try:
                        visualizer = NetworkVisualizer()
                        
                        # Filter data based on score
                        filtered_corr = st.session_state.correlation_results[
                            st.session_state.correlation_results['total_score'] >= min_score_filter
                        ].copy()
                        
                        if visualization_type == "Simple Network Graph":
                            # Create simple network graph
                            if not filtered_corr.empty:
                                fig = visualizer.create_simple_network_graph(
                                    filtered_corr,
                                    st.session_state.tor_nodes_df
                                )
                                st.plotly_chart(fig, use_container_width=True)
                            else:
                                st.warning("No correlations found with selected score threshold")
                        
                        elif visualization_type == "Compact IP Diagram":
                            # Create compact IP diagram (like the example image)
                            if not filtered_corr.empty:
                                fig = visualizer.create_compact_network_diagram(filtered_corr)
                                st.plotly_chart(fig, use_container_width=True)
                            else:
                                st.warning("No correlations found with selected score threshold")
                        
                        elif visualization_type == "Tor Node Network":
                            # Tor node analysis
                            if st.session_state.tor_nodes_df is not None and not st.session_state.tor_nodes_df.empty:
                                # Country distribution
                                country_counts = st.session_state.tor_nodes_df['country_name'].value_counts().head(15)
                                
                                fig = px.treemap(
                                    names=country_counts.index,
                                    values=country_counts.values,
                                    title="Tor Nodes by Country",
                                    color=country_counts.values,
                                    color_continuous_scale='Blues'
                                )
                                st.plotly_chart(fig, use_container_width=True)
                            else:
                                st.warning("No Tor node data available")
                        
                        else:  # Path Hops
                            if 'path_results' in st.session_state:
                                # Show path distribution
                                path_results = st.session_state.path_results
                                paths = path_results.get('paths', [])
                                
                                if paths:
                                    hop_counts = [p.get('hop_count', 0) for p in paths]
                                    
                                    fig = px.histogram(
                                        x=hop_counts,
                                        nbins=10,
                                        title="Distribution of Path Hops",
                                        labels={'x': 'Number of Hops', 'y': 'Frequency'},
                                        color_discrete_sequence=['#4ECDC4']
                                    )
                                    st.plotly_chart(fig, use_container_width=True)
                                else:
                                    st.warning("No path data available. Reconstruct paths first.")
                            else:
                                st.warning("No path results. Run path reconstruction first.")
                        
                        st.success("✅ Visualization generated!")
                        
                    except Exception as e:
                        st.error(f"Error generating visualization: {e}")
                        import traceback
                        st.code(traceback.format_exc())
            
            # Statistics panel
            st.markdown("### 📊 Visualization Statistics")
            
            stats_col1, stats_col2, stats_col3 = st.columns(3)
            
            with stats_col1:
                if st.session_state.correlation_results is not None:
                    total_corr = len(st.session_state.correlation_results)
                    filtered_count = len(st.session_state.correlation_results[
                        st.session_state.correlation_results['total_score'] >= min_score_filter
                    ])
                    st.metric(
                        "Correlations Displayed",
                        filtered_count,
                        delta=f"{total_corr} total"
                    )
            
            with stats_col2:
                if st.session_state.correlation_results is not None:
                    unique_ips = len(set(
                        list(st.session_state.correlation_results['src_ip'].unique()) +
                        list(st.session_state.correlation_results['dst_ip'].unique())
                    ))
                    st.metric("Unique IPs", unique_ips)
            
            with stats_col3:
                if st.session_state.correlation_results is not None:
                    unique_nodes = st.session_state.correlation_results['tor_node_name'].nunique()
                    st.metric("Unique Tor Nodes", unique_nodes)
            
            # Add a sample visualization if no data is loaded
            if st.session_state.correlation_results is None:
                st.markdown("### 🎯 Sample Visualization")
                st.info("This is how your network graph will look once you load data")
                
                # Create a sample visualization
                sample_data = {
                    'src_ip': ['192.168.1.100', '192.168.1.101', '10.0.0.1'],
                    'tor_node_ip': ['185.220.101.1', '185.220.101.2', '185.220.101.3'],
                    'dst_ip': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
                    'total_score': [0.85, 0.72, 0.65]
                }
                sample_df = pd.DataFrame(sample_data)
                
                visualizer = NetworkVisualizer()
                sample_fig = visualizer.create_compact_network_diagram(sample_df)
                st.plotly_chart(sample_fig, use_container_width=True)


# Run the app
if __name__ == "__main__":
    main()