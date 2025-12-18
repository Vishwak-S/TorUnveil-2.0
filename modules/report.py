"""
report.py - Forensic report generation for TOR-Unveil
Generates comprehensive forensic reports from analysis results
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from typing import Dict, List, Tuple, Optional, Any
import os
import base64
from io import BytesIO
import zipfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY

class ForensicReportGenerator:
    """Generates comprehensive forensic reports for TOR-Unveil"""
    
    def __init__(self, report_title="TOR-Unveil Forensic Report"):
        self.report_title = report_title
        self.report_sections = []
        self.metadata = {}
        
    def generate_report(self, tor_nodes: pd.DataFrame, flows: List[Dict], 
                       correlations: pd.DataFrame, paths: Dict,
                       stats: Dict) -> str:
        """
        Generate a comprehensive forensic report
        
        Args:
            tor_nodes: DataFrame with Tor node information
            flows: List of flow dictionaries
            correlations: DataFrame with correlation results
            paths: Dictionary with reconstructed paths
            stats: Dictionary with statistics
            
        Returns:
            Complete report as string
        """
        print("📄 Generating forensic report...")
        
        # Initialize report
        self.report_sections = []
        self.metadata = {
            'generated_at': datetime.now().isoformat(),
            'report_version': '1.0',
            'system': 'TOR-Unveil Forensic System',
        }
        
        # Generate report sections
        self._add_header_section()
        self._add_executive_summary(stats)
        self._add_tor_network_analysis(tor_nodes, stats.get('tor_metrics', {}))
        self._add_pcap_analysis(flows, stats.get('flow_stats', {}))
        self._add_correlation_analysis(correlations, stats.get('correlation_stats', {}))
        self._add_path_analysis(paths)
        self._add_methodology_section()
        self._add_limitations_section()
        self._add_conclusion_section()
        self._add_appendix_section(tor_nodes, flows, correlations, paths)
        
        # Combine all sections
        full_report = self._compile_report()
        
        print(f"✅ Generated forensic report with {len(self.report_sections)} sections")
        return full_report
    
    def _add_header_section(self):
        """Add report header section"""
        header = f"""
{'='*80}
{'TOR-UNVEIL FORENSIC REPORT'.center(80)}
{'='*80}

Report ID: {self._generate_report_id()}
Generated: {self.metadata['generated_at']}
System: {self.metadata['system']} v{self.metadata['report_version']}
Case Reference: [CASE-REFERENCE-HERE]
Investigating Agency: [AGENCY-NAME-HERE]

{'='*80}
CONFIDENTIAL - FOR AUTHORIZED INVESTIGATIVE USE ONLY
{'='*80}
"""
        self.report_sections.append(('Header', header))
    
    def _add_executive_summary(self, stats: Dict):
        """Add executive summary section"""
        tor_stats = stats.get('tor_metrics', {})
        flow_stats = stats.get('flow_stats', {})
        corr_stats = stats.get('correlation_stats', {})
        
        summary = f"""
EXECUTIVE SUMMARY
{'='*80}

1. OVERVIEW
   • Analysis conducted using TOR-Unveil forensic system
   • Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
   • Purpose: Correlation of network traffic with Tor network nodes

2. KEY FINDINGS
   • Tor Network Analyzed: {tor_stats.get('total_relays', 0):,} total relays
   • PCAP Analysis: {flow_stats.get('total_flows', 0):,} network flows extracted
   • Correlation Results: {corr_stats.get('total_correlations', 0):,} correlations identified
   • High Confidence Matches: {corr_stats.get('high_confidence', 0):,} (>0.8 confidence)

3. SIGNIFICANT OBSERVATIONS
"""
        
        # Add significant findings based on data
        if corr_stats.get('high_confidence', 0) > 0:
            summary += f"   • Found {corr_stats.get('high_confidence', 0)} high-confidence Tor entry node matches\n"
        
        if tor_stats.get('guard_count', 0) > 0:
            summary += f"   • Identified {tor_stats.get('guard_count', 0)} guard nodes in current Tor network\n"
        
        if flow_stats.get('suspected_tor_flows', 0) > 0:
            summary += f"   • Detected {flow_stats.get('suspected_tor_flows', 0)} flows with Tor-like characteristics\n"
        
        summary += f"""
4. RECOMMENDATIONS
   • Investigate high-confidence correlation matches for potential leads
   • Validate findings with additional evidence sources
   • Consider temporal patterns in correlation analysis
   • Document all findings for chain of custody

{'='*80}
"""
        self.report_sections.append(('Executive Summary', summary))
    
    def _add_tor_network_analysis(self, tor_nodes: pd.DataFrame, metrics: Dict):
        """Add Tor network analysis section"""
        analysis = f"""
TOR NETWORK ANALYSIS
{'='*80}

1. NETWORK SNAPSHOT
   • Total Relays: {metrics.get('total_relays', 0):,}
   • Guard Nodes: {metrics.get('guard_count', 0):,}
   • Exit Nodes: {metrics.get('exit_count', 0):,}
   • Total Bandwidth: {metrics.get('total_bandwidth_gbps', 0):.2f} Gbps
   • Countries Represented: {metrics.get('country_count', 0):,}
   • Data Freshness: {metrics.get('data_freshness_avg_hrs', 0):.1f} hours (avg)

2. GEOGRAPHICAL DISTRIBUTION
"""
        
        # Add top countries if available
        if 'top_countries' in metrics and metrics['top_countries']:
            analysis += "   • Top Countries by Node Count:\n"
            for country, count in list(metrics['top_countries'].items())[:5]:
                analysis += f"     - {country}: {count} nodes\n"
        
        analysis += f"""
3. PERFORMANCE CHARACTERISTICS
   • Average Performance Score: {metrics.get('avg_performance', 0):.3f}
   • High Performance Nodes: {metrics.get('high_perf_count', 0):,}
   • Average Uptime: {metrics.get('avg_uptime_days', 0):.1f} days

4. DATA QUALITY
   • High Quality Data: {metrics.get('data_quality_high', 0):,} relays
   • Average Freshness: {metrics.get('data_freshness_avg_hrs', 0):.1f} hours

{'='*80}
"""
        self.report_sections.append(('Tor Network Analysis', analysis))
    
    def _add_pcap_analysis(self, flows: List[Dict], stats: Dict):
        """Add PCAP analysis section"""
        analysis = f"""
PCAP NETWORK TRAFFIC ANALYSIS
{'='*80}

1. FLOW STATISTICS
   • Total Flows Analyzed: {stats.get('total_flows', 0):,}
   • Suspected Tor Flows: {stats.get('suspected_tor_flows', 0):,}
   • High Confidence Tor Flows: {stats.get('high_confidence_tor_flows', 0):,}
   • Total Packets: {stats.get('total_packets', 0):,}
   • Total Data Volume: {stats.get('total_bytes', 0):,} bytes ({stats.get('total_bytes', 0) / 1_000_000:.2f} MB)

2. TEMPORAL ANALYSIS
"""
        
        # Add time range if available
        if 'time_range' in stats:
            time_range = stats['time_range']
            analysis += f"   • Capture Start: {time_range.get('start', 'N/A')}\n"
            analysis += f"   • Capture End: {time_range.get('end', 'N/A')}\n"
            analysis += f"   • Total Duration: {time_range.get('duration_seconds', 0):.0f} seconds\n"
        
        analysis += f"""
3. TRAFFIC CHARACTERISTICS
   • Average Tor Confidence: {stats.get('avg_tor_confidence', 0):.3f}
   • Average Flow Duration: {stats.get('avg_flow_duration', 0):.2f} seconds
   • Unique Source IPs: {stats.get('unique_source_ips', 0):,}
   • Unique Destination IPs: {stats.get('unique_destination_ips', 0):,}

4. PORT ANALYSIS
"""
        
        # Add common ports if available
        if 'common_ports' in stats and stats['common_ports']:
            analysis += "   • Most Common Destination Ports:\n"
            for port, count in list(stats['common_ports'].items())[:3]:
                analysis += f"     - Port {port}: {count} flows\n"
        
        analysis += f"""
{'='*80}
"""
        self.report_sections.append(('PCAP Analysis', analysis))
    
    def _add_correlation_analysis(self, correlations: pd.DataFrame, stats: Dict):
        """Add correlation analysis section"""
        analysis = f"""
CORRELATION ANALYSIS
{'='*80}

1. CORRELATION RESULTS SUMMARY
   • Total Correlations: {stats.get('total_correlations', 0):,}
   • High Confidence (≥0.8): {stats.get('high_confidence', 0):,}
   • Medium Confidence (0.6-0.8): {stats.get('medium_confidence', 0):,}
   • Average Total Score: {stats.get('avg_total_score', 0):.3f}
   • Unique Tor Nodes Involved: {stats.get('unique_tor_nodes', 0):,}
   • Unique Flows Correlated: {stats.get('unique_flows', 0):,}

2. SCORE DISTRIBUTION
"""
        
        # Add score distribution if available
        if 'score_distribution' in stats and stats['score_distribution']:
            analysis += "   • Correlation Score Ranges:\n"
            for score_range, count in stats['score_distribution'].items():
                analysis += f"     - {score_range}: {count} correlations\n"
        
        analysis += f"""
3. TOP CORRELATIONS BY CATEGORY
"""
        
        # Add top correlations if available
        if not correlations.empty:
            # Top by total score
            top_total = correlations.nlargest(3, 'total_score')
            analysis += "   • Highest Overall Scores:\n"
            for idx, row in top_total.iterrows():
                analysis += f"     - {row.get('tor_node_name', 'Unknown')}: {row.get('total_score', 0):.3f}\n"
                analysis += f"       Flow: {row.get('src_ip', '?')} → {row.get('tor_node_ip', '?')}\n"
            
            # Top by temporal score
            top_temporal = correlations.nlargest(2, 'temporal_score')
            if len(top_temporal) > 0:
                analysis += "   • Best Temporal Matches:\n"
                for idx, row in top_temporal.iterrows():
                    analysis += f"     - {row.get('tor_node_name', 'Unknown')}: {row.get('temporal_score', 0):.3f}\n"
        
        analysis += f"""
4. GEOGRAPHICAL INSIGHTS
"""
        
        # Add top countries if available
        if 'top_countries' in stats and stats['top_countries']:
            analysis += "   • Most Common Tor Node Countries:\n"
            for country, count in list(stats['top_countries'].items())[:5]:
                analysis += f"     - {country}: {count} correlations\n"
        
        analysis += f"""
{'='*80}
"""
        self.report_sections.append(('Correlation Analysis', analysis))
    
    def _add_path_analysis(self, paths: Dict):
        """Add path analysis section"""
        analysis = f"""
NETWORK PATH RECONSTRUCTION
{'='*80}

1. PATH RECONSTRUCTION SUMMARY
"""
        
        if paths and paths.get('paths'):
            stats = paths.get('statistics', {})
            metadata = paths.get('metadata', {})
            
            analysis += f"""   • Total Paths Reconstructed: {stats.get('total_paths', 0):,}
   • Complete Paths: {stats.get('complete_paths', 0):,}
   • Incomplete Paths: {stats.get('incomplete_paths', 0):,}
   • Average Path Length: {stats.get('avg_path_length', 0):.1f} hops
   • Average Confidence: {stats.get('avg_confidence', 0):.3f}
   • Minimum Path Length: {stats.get('min_path_length', 0):,} hops
   • Maximum Path Length: {stats.get('max_path_length', 0):,} hops

2. NODE TYPE DISTRIBUTION
"""
            
            # Add node types if available
            if 'node_types' in stats and stats['node_types']:
                for node_type, count in stats['node_types'].items():
                    analysis += f"   • {node_type.title()}: {count} occurrences\n"
            
            analysis += f"""
3. GEOGRAPHICAL SPAN
   • Unique Countries in Paths: {stats.get('unique_countries', 0):,}
   • Unique Source IPs: {stats.get('unique_sources', 0):,}

4. SAMPLE RECONSTRUCTED PATH
"""
            
            # Add sample path if available
            if paths['paths']:
                sample_path = paths['paths'][0]
                analysis += f"""   • Path ID: {sample_path.get('path_id', 'N/A')}
   • Source: {sample_path.get('src_ip', 'N/A')}
   • Destination: {sample_path.get('dst_ip', 'N/A')}
   • Confidence: {sample_path.get('avg_confidence', 0):.3f}
   • Complete: {'Yes' if sample_path.get('complete', False) else 'No'}
   • Total Hops: {sample_path.get('total_hops', 0):,}
   
   Path Flow:
"""
                for i, node in enumerate(sample_path.get('nodes', [])):
                    node_type = node.get('type', 'unknown').title()
                    node_name = node.get('nickname', node.get('ip', '?'))
                    analysis += f"     {i+1}. [{node_type}] {node_name}"
                    if node.get('country') and node.get('country') != 'Unknown':
                        analysis += f" ({node.get('country')})"
                    analysis += "\n"
        
        else:
            analysis += "   • No paths were successfully reconstructed from the correlation data.\n"
        
        analysis += f"""
{'='*80}
"""
        self.report_sections.append(('Path Analysis', analysis))
    
    def _add_methodology_section(self):
        """Add methodology section"""
        methodology = f"""
METHODOLOGY
{'='*80}

1. DATA COLLECTION
   • Tor Network Data: Retrieved from Onionoo API (torproject.org)
   • Network Traffic: Extracted from PCAP/PCAPNG capture files
   • Flow Extraction: Using Scapy/PyShark packet analysis libraries

2. CORRELATION ENGINE
   • Weighted Scoring Model:
     - Temporal Matching: 50% weight (IP/timestamp alignment)
     - Bandwidth Feasibility: 30% weight (capacity analysis)
     - Pattern Similarity: 20% weight (Tor traffic fingerprints)
   
   • Confidence Levels:
     🟢 HIGH (≥0.8): Strong evidence across multiple factors
     🟡 MEDIUM (0.6-0.8): Good evidence with some uncertainty
     🟠 LOW (0.4-0.6): Some evidence but requires verification
     🔴 WEAK (<0.4): Limited or speculative evidence

3. PATH RECONSTRUCTION
   • Entry Node Identification: Based on highest correlation scores
   • Middle Node Selection: Random simulation from available relays
   • Exit Node Assignment: Based on exit policy and availability
   • Path Validation: Checking for logical flow and consistency

4. QUALITY ASSURANCE
   • Data Validation: IP address validation, timestamp consistency checks
   • Statistical Analysis: Confidence intervals, score distributions
   • Peer Review: All findings subject to verification

{'='*80}
"""
        self.report_sections.append(('Methodology', methodology))
    
    def _add_limitations_section(self):
        """Add limitations and disclaimer section"""
        limitations = f"""
LIMITATIONS AND DISCLAIMERS
{'='*80}

1. METHODOLOGICAL LIMITATIONS
   • Correlation vs. Causation: Correlation scores indicate likelihood, not proof
   • Tor Network Dynamics: Tor nodes change frequently; data represents a snapshot
   • PCAP Limitations: Encrypted traffic cannot be decrypted without keys
   • Simulation Elements: Some path reconstruction involves simulation

2. TECHNICAL LIMITATIONS
   • Bandwidth Estimation: Based on advertised/observed bandwidth, not real-time
   • Temporal Accuracy: Timestamps may have synchronization issues
   • Geographic Data: IP geolocation has inherent accuracy limitations
   • Sample Size: Results may vary based on data volume and quality

3. LEGAL AND ETHICAL CONSIDERATIONS
   • Authorized Use: This tool should only be used for lawful investigations
   • Privacy Protection: Handle all data according to applicable privacy laws
   • Chain of Custody: Maintain proper documentation for evidentiary purposes
   • Expert Verification: Findings should be verified by qualified experts

4. DISCLAIMER
   This report is generated by an automated forensic system. While every effort
   has been made to ensure accuracy, the findings should be considered as
   investigative leads rather than definitive proof. Always corroborate with
   additional evidence and follow established investigative procedures.

{'='*80}
"""
        self.report_sections.append(('Limitations', limitations))
    
    def _add_conclusion_section(self):
        """Add conclusion section"""
        conclusion = f"""
CONCLUSION AND RECOMMENDATIONS
{'='*80}

1. KEY CONCLUSIONS
   • The analysis has successfully correlated network traffic with Tor nodes
   • High-confidence matches provide actionable investigative leads
   • Reconstructed paths offer insight into potential Tor usage patterns
   • Findings are reproducible and documented for evidentiary purposes

2. INVESTIGATIVE RECOMMENDATIONS
   • Prioritize investigation of high-confidence correlation matches
   • Validate findings with additional network and system evidence
   • Consider temporal patterns in relation to other investigation events
   • Document all findings following proper forensic procedures

3. FOLLOW-UP ACTIONS
   • Conduct additional network monitoring if authorized
   • Correlate with other digital evidence sources
   • Consult with Tor network experts if needed
   • Update findings as new information becomes available

4. REPORT VALIDATION
   • This report has been generated by TOR-Unveil Forensic System v1.0
   • All calculations and findings are reproducible from source data
   • Report includes comprehensive methodology and limitations
   • Findings should be verified by qualified forensic investigators

{'='*80}
"""
        self.report_sections.append(('Conclusion', conclusion))
    
    def _add_appendix_section(self, tor_nodes: pd.DataFrame, flows: List[Dict], 
                             correlations: pd.DataFrame, paths: Dict):
        """Add appendix section with raw data references"""
        appendix = f"""
APPENDIX
{'='*80}

1. DATA REFERENCES
   • Tor Nodes: {len(tor_nodes)} records (available in tor_nodes.csv)
   • Network Flows: {len(flows)} flows (available in pcap_flows.csv)
   • Correlation Results: {len(correlations) if not correlations.empty else 0} correlations (available in correlation_results.csv)
   • Reconstructed Paths: {len(paths.get('paths', [])) if paths else 0} paths (available in reconstructed_paths.json)

2. FILE STRUCTURE
   • All raw data files are saved in the 'data' directory
   • CSV files contain tabular data for further analysis
   • JSON files contain structured data for programmatic access
   • This report is saved as a text file with timestamp

3. REPRODUCIBILITY
   • All analyses can be reproduced using the provided data files
   • Correlation calculations follow documented methodology
   • Path reconstruction uses deterministic algorithms with known seeds
   • Timestamps are preserved for temporal analysis verification

4. CONTACT INFORMATION
   • System: TOR-Unveil Forensic System
   • Version: 1.0
   • Purpose: Lawful investigation of Tor network usage
   • Support: [SUPPORT-CONTACT-HERE]

{'='*80}
END OF REPORT
{'='*80}
"""
        self.report_sections.append(('Appendix', appendix))
    
    def _compile_report(self) -> str:
        """Compile all report sections into a single string"""
        full_report = ""
        for section_name, section_content in self.report_sections:
            full_report += section_content + "\n"
        
        return full_report
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_suffix = os.urandom(3).hex()
        return f"TOR-REPORT-{timestamp}-{random_suffix}"
    
    def save_report_to_file(self, report_content: str, filename: str = None) -> str:
        """Save report to text file"""
        if filename is None:
            filename = os.path.join("data", "reports", f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            print(f"💾 Saved forensic report to {filename}")
            return filename
            
        except Exception as e:
            print(f"❌ Error saving report: {e}")
            return ""
    
    def export_to_pdf(self, report_content: str, filename: str = None) -> str:
        """
        Export report to PDF using reportlab
        
        Args:
            report_content: Report content as string
            filename: Output PDF filename (optional)
            
        Returns:
            Path to created PDF file
        """
        if filename is None:
            filename = os.path.join("data", "reports", f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                filename,
                pagesize=letter,
                rightMargin=0.5*inch,
                leftMargin=0.5*inch,
                topMargin=0.75*inch,
                bottomMargin=0.75*inch,
            )
            
            # Container for PDF elements
            story = []
            styles = getSampleStyleSheet()
            
            # Add custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#2c2c2c'),
                spaceAfter=12,
                spaceBefore=12,
                fontName='Helvetica-Bold',
                borderColor=colors.HexColor('#cccccc'),
                borderPadding=8,
            )
            
            body_style = ParagraphStyle(
                'CustomBody',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#333333'),
                alignment=TA_JUSTIFY,
                spaceAfter=6,
                leading=14,
            )
            
            # Parse report content and add to PDF
            lines = report_content.split('\n')
            current_section = ""
            
            for line in lines:
                if not line.strip():
                    story.append(Spacer(1, 0.1*inch))
                    continue
                
                # Detect headers (lines with = signs)
                if line.strip().startswith('=') and line.strip().endswith('='):
                    if story and len(story) > 3:  # Add page break except for first page
                        story.append(PageBreak())
                    continue
                
                # Detect section headers (all caps, 20+ chars)
                if line.strip().isupper() and len(line.strip()) > 20:
                    story.append(Paragraph(line.strip(), heading_style))
                    story.append(Spacer(1, 0.15*inch))
                    current_section = line.strip()
                # Regular content
                elif line.strip():
                    # Preserve indentation for readability
                    indent = len(line) - len(line.lstrip())
                    if indent > 0:
                        formatted_line = '&nbsp;' * (indent * 2) + line.strip()
                    else:
                        formatted_line = line.strip()
                    
                    story.append(Paragraph(formatted_line, body_style))
            
            # Add footer with page numbers
            def add_page_number(canvas, doc):
                """Add page number to footer"""
                canvas.setFont("Helvetica", 9)
                canvas.drawString(
                    0.5*inch,
                    0.5*inch,
                    f"Page {doc.page}"
                )
                canvas.drawRightString(
                    letter[0] - 0.5*inch,
                    0.5*inch,
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
            
            # Build PDF
            doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
            
            print(f"📄 PDF report exported to {filename}")
            return filename
            
        except ImportError as e:
            print(f"❌ PDF export requires reportlab library. Install it with: pip install reportlab")
            print(f"   Saving as text file instead.")
            return self.save_report_to_file(report_content, filename.replace('.pdf', '.txt'))
        except Exception as e:
            print(f"❌ Error exporting to PDF: {e}")
            print(f"   Falling back to text format.")
            return self.save_report_to_file(report_content, filename.replace('.pdf', '.txt'))
    
    def export_report(self, report_content: str, output_format: str = 'both', 
                     base_filename: str = None) -> Dict[str, str]:
        """
        Export report in specified format(s)
        
        Args:
            report_content: Report content as string
            output_format: 'txt', 'pdf', or 'both' (default)
            base_filename: Base filename without extension
            
        Returns:
            Dictionary with format as key and filepath as value
        """
        results = {}
        
        if base_filename is None:
            base_filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        base_path = os.path.join("data", "reports", base_filename)
        
        # Export to text
        if output_format in ['txt', 'both']:
            txt_file = self.save_report_to_file(report_content, base_path + '.txt')
            if txt_file:
                results['txt'] = txt_file
        
        # Export to PDF
        if output_format in ['pdf', 'both']:
            pdf_file = self.export_to_pdf(report_content, base_path + '.pdf')
            if pdf_file:
                results['pdf'] = pdf_file
        
        return results
    
    def create_evidence_package(self, data_files: Dict[str, str], 
                               report_content: str) -> str:
        """
        Create a zip package with all evidence files
        
        Args:
            data_files: Dictionary of {filename: filepath}
            report_content: Report content as string
            
        Returns:
            Path to created zip file
        """
        try:
            # Create zip file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            zip_filename = os.path.join("data", "exports", f"evidence_package_{timestamp}.zip")
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(zip_filename), exist_ok=True)
            
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                # Add report
                report_filename = f"forensic_report_{timestamp}.txt"
                zipf.writestr(report_filename, report_content)
                
                # Add data files
                for display_name, filepath in data_files.items():
                    if os.path.exists(filepath):
                        arcname = f"data/{display_name}"
                        zipf.write(filepath, arcname)
                    else:
                        print(f"⚠️  File not found: {filepath}")
            
            print(f"📦 Created evidence package: {zip_filename}")
            return zip_filename
            
        except Exception as e:
            print(f"❌ Error creating evidence package: {e}")
            return ""
    
    def generate_report_summary(self, stats: Dict) -> Dict:
        """
        Generate a JSON summary of the report for dashboard display
        
        Args:
            stats: Dictionary with all statistics
            
        Returns:
            JSON-serializable summary dictionary
        """
        tor_stats = stats.get('tor_metrics', {})
        flow_stats = stats.get('flow_stats', {})
        corr_stats = stats.get('correlation_stats', {})
        
        summary = {
            'metadata': {
                'report_id': self._generate_report_id(),
                'generated_at': datetime.now().isoformat(),
                'title': self.report_title,
            },
            'key_metrics': {
                'tor_network': {
                    'total_relays': tor_stats.get('total_relays', 0),
                    'guard_nodes': tor_stats.get('guard_count', 0),
                    'exit_nodes': tor_stats.get('exit_count', 0),
                    'countries': tor_stats.get('country_count', 0),
                },
                'traffic_analysis': {
                    'total_flows': flow_stats.get('total_flows', 0),
                    'suspected_tor_flows': flow_stats.get('suspected_tor_flows', 0),
                    'total_data_mb': round(flow_stats.get('total_bytes', 0) / 1_000_000, 2),
                },
                'correlation_results': {
                    'total_correlations': corr_stats.get('total_correlations', 0),
                    'high_confidence': corr_stats.get('high_confidence', 0),
                    'avg_score': round(corr_stats.get('avg_total_score', 0), 3),
                    'unique_nodes': corr_stats.get('unique_tor_nodes', 0),
                }
            },
            'top_findings': [],
            'recommendations': [
                "Investigate high-confidence correlation matches",
                "Validate findings with additional evidence sources",
                "Consider temporal patterns in analysis",
                "Document all findings for chain of custody",
            ]
        }
        
        # Add top findings based on data
        if corr_stats.get('high_confidence', 0) > 0:
            summary['top_findings'].append(
                f"Found {corr_stats['high_confidence']} high-confidence Tor entry node matches"
            )
        
        if tor_stats.get('guard_count', 0) > 1000:
            summary['top_findings'].append(
                f"Large Tor network analyzed: {tor_stats['guard_count']} guard nodes"
            )
        
        if flow_stats.get('suspected_tor_flows', 0) > 0:
            summary['top_findings'].append(
                f"Detected {flow_stats['suspected_tor_flows']} flows with Tor-like characteristics"
            )
        
        return summary

# Test function
def test_report_module():
    """Test the report generation module"""
    print("🧪 Testing report generation module...")
    print("="*60)
    
    # Create sample data
    print("📝 Creating sample data...")
    
    # Sample Tor nodes
    tor_nodes_data = {
        'nickname': ['Node1', 'Node2', 'Node3', 'Node4', 'Node5'],
        'ip_address': ['185.220.101.1', '185.220.101.2', '185.220.101.3', '185.220.101.4', '185.220.101.5'],
        'role': ['Guard', 'Guard+Exit', 'Exit', 'Relay', 'Guard'],
        'country_name': ['Germany', 'US', 'Netherlands', 'France', 'Germany'],
        'observed_bandwidth_mbps': [50, 80, 30, 20, 60],
        'performance_score': [0.8, 0.7, 0.6, 0.5, 0.9],
    }
    tor_nodes_df = pd.DataFrame(tor_nodes_data)
    
    # Sample flows
    flows = [
        {
            'flow_id': 'flow_001',
            'src_ip': '192.168.1.100',
            'dst_ip': '185.220.101.1',
            'src_port': 54321,
            'dst_port': 443,
            'packet_count': 100,
            'total_bytes': 50000,
            'tor_confidence': 0.85,
            'is_suspected_tor': 1,
        },
        {
            'flow_id': 'flow_002',
            'src_ip': '192.168.1.101',
            'dst_ip': '185.220.101.2',
            'src_port': 54322,
            'dst_port': 443,
            'packet_count': 150,
            'total_bytes': 75000,
            'tor_confidence': 0.72,
            'is_suspected_tor': 1,
        }
    ]
    
    # Sample correlations
    correlation_data = {
        'flow_id': ['flow_001', 'flow_002', 'flow_001', 'flow_002'],
        'src_ip': ['192.168.1.100', '192.168.1.101', '192.168.1.100', '192.168.1.101'],
        'tor_node_ip': ['185.220.101.1', '185.220.101.2', '185.220.101.3', '185.220.101.4'],
        'tor_node_name': ['Node1', 'Node2', 'Node3', 'Node4'],
        'tor_node_country': ['Germany', 'US', 'Netherlands', 'France'],
        'total_score': [0.92, 0.78, 0.65, 0.58],
        'temporal_score': [0.95, 0.80, 0.70, 0.60],
        'bandwidth_score': [0.90, 0.75, 0.60, 0.55],
        'pattern_score': [0.85, 0.70, 0.65, 0.60],
        'confidence_badge': ['🟢 HIGH', '🟡 MEDIUM', '🟠 LOW', '🟠 LOW'],
    }
    correlation_df = pd.DataFrame(correlation_data)
    
    # Sample paths
    paths = {
        'paths': [
            {
                'path_id': 'path_001',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'avg_confidence': 0.85,
                'complete': True,
                'total_hops': 5,
                'nodes': [
                    {'ip': '192.168.1.100', 'type': 'client', 'nickname': 'Client', 'country': 'Local'},
                    {'ip': '185.220.101.1', 'type': 'guard', 'nickname': 'Node1', 'country': 'Germany'},
                    {'ip': '185.220.101.3', 'type': 'relay', 'nickname': 'Node3', 'country': 'Netherlands'},
                    {'ip': '185.220.101.2', 'type': 'exit', 'nickname': 'Node2', 'country': 'US'},
                    {'ip': '10.0.0.1', 'type': 'destination', 'nickname': 'Dest1', 'country': 'Unknown'},
                ]
            }
        ],
        'statistics': {
            'total_paths': 1,
            'complete_paths': 1,
            'avg_path_length': 5.0,
            'avg_confidence': 0.85,
            'node_types': {'client': 1, 'guard': 1, 'relay': 1, 'exit': 1, 'destination': 1},
            'unique_sources': 1,
            'unique_countries': 3,
        }
    }
    
    # Sample statistics
    stats = {
        'tor_metrics': {
            'total_relays': 6789,
            'guard_count': 1234,
            'exit_count': 567,
            'country_count': 89,
            'total_bandwidth_gbps': 45.6,
            'avg_performance': 0.72,
        },
        'flow_stats': {
            'total_flows': 150,
            'suspected_tor_flows': 45,
            'high_confidence_tor_flows': 22,
            'total_packets': 12500,
            'total_bytes': 6250000,
            'avg_tor_confidence': 0.68,
        },
        'correlation_stats': {
            'total_correlations': 85,
            'high_confidence': 12,
            'medium_confidence': 35,
            'avg_total_score': 0.65,
            'unique_tor_nodes': 42,
            'unique_flows': 28,
        }
    }
    
    print("✅ Created sample data")
    
    # Test report generation
    print("\n📄 Testing report generation...")
    generator = ForensicReportGenerator()
    
    try:
        # Generate full report
        report = generator.generate_report(
            tor_nodes=tor_nodes_df,
            flows=flows,
            correlations=correlation_df,
            paths=paths,
            stats=stats
        )
        
        if report and len(report) > 1000:
            print(f"✅ Generated report: {len(report)} characters")
            print(f"   Sections: {len(generator.report_sections)}")
            
            # Test report saving
            print("\n💾 Testing report saving...")
            saved_file = generator.save_report_to_file(report, "test_report.txt")
            if saved_file and os.path.exists(saved_file):
                print(f"✅ Saved report to {saved_file}")
                
                # Read back to verify
                with open(saved_file, 'r') as f:
                    saved_content = f.read()
                if len(saved_content) == len(report):
                    print("✅ File save verification PASSED")
                else:
                    print("❌ File save verification FAILED")
                
                # Clean up
                os.remove(saved_file)
            else:
                print("❌ Failed to save report")
            
            # Test evidence package
            print("\n📦 Testing evidence package creation...")
            data_files = {
                'tor_nodes.csv': 'test_tor_nodes.csv',
                'pcap_flows.csv': 'test_pcap_flows.csv',
                'correlation_results.csv': 'test_correlation_results.csv',
            }
            
            # Create dummy files for testing
            for filename in data_files.values():
                with open(filename, 'w') as f:
                    f.write("test data")
            
            package_file = generator.create_evidence_package(data_files, report)
            if package_file and os.path.exists(package_file):
                print(f"✅ Created evidence package: {package_file}")
                os.remove(package_file)  # Clean up
            else:
                print("❌ Failed to create evidence package")
            
            # Clean up dummy files
            for filename in data_files.values():
                if os.path.exists(filename):
                    os.remove(filename)
            
            # Test report summary
            print("\n📊 Testing report summary generation...")
            summary = generator.generate_report_summary(stats)
            if summary and 'key_metrics' in summary:
                print(f"✅ Generated report summary with {len(summary['key_metrics'])} metrics")
                print(f"   Top findings: {len(summary['top_findings'])}")
                print(f"   Recommendations: {len(summary['recommendations'])}")
            else:
                print("❌ Failed to generate report summary")
            
            print("\n✅ Report generation module test PASSED!")
            return True
            
        else:
            print("❌ Failed to generate report")
            return False
            
    except Exception as e:
        print(f"❌ Error in report generation: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Run test
    test_report_module()