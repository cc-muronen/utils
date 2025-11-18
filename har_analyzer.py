#!/usr/bin/env python3
"""
HAR File Analyzer
Extracts and analyzes download and operation times from HAR (HTTP Archive) files.
"""

import json
import sys
from typing import Dict, List, Any
from dataclasses import dataclass
from statistics import mean, median, stdev
from pathlib import Path


@dataclass
class TimingInfo:
    """Holds timing information for a single HTTP request"""
    url: str
    method: str
    status: int
    total_time: float  # milliseconds
    blocked: float
    dns: float
    connect: float
    send: float
    wait: float
    receive: float
    ssl: float


class HARAnalyzer:
    """Analyzes HAR files and extracts timing statistics"""
    
    def __init__(self, har_file_path: str):
        self.har_file_path = Path(har_file_path)
        self.entries: List[TimingInfo] = []
        
    def load_har(self) -> Dict[str, Any]:
        """Load and parse the HAR file"""
        try:
            with open(self.har_file_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)
            return har_data
        except FileNotFoundError:
            print(f"Error: File '{self.har_file_path}' not found.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in HAR file: {e}")
            sys.exit(1)
    
    def extract_timings(self) -> None:
        """Extract timing information from HAR entries"""
        har_data = self.load_har()
        
        if 'log' not in har_data or 'entries' not in har_data['log']:
            print("Error: Invalid HAR file format")
            sys.exit(1)
        
        entries = har_data['log']['entries']
        
        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})
            timings = entry.get('timings', {})
            
            # Extract timing values (use 0 if not present or -1)
            def get_timing(key: str) -> float:
                value = timings.get(key, 0)
                return max(0, value)  # Convert -1 to 0 (meaning not applicable)
            
            timing_info = TimingInfo(
                url=request.get('url', 'unknown'),
                method=request.get('method', 'unknown'),
                status=response.get('status', 0),
                total_time=entry.get('time', 0),
                blocked=get_timing('blocked'),
                dns=get_timing('dns'),
                connect=get_timing('connect'),
                send=get_timing('send'),
                wait=get_timing('wait'),
                receive=get_timing('receive'),
                ssl=get_timing('ssl')
            )
            
            self.entries.append(timing_info)
    
    def calculate_statistics(self) -> Dict[str, Dict[str, float]]:
        """Calculate statistics for all timing phases"""
        if not self.entries:
            return {}
        
        timing_phases = ['total_time', 'blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl']
        stats = {}
        
        for phase in timing_phases:
            values = [getattr(entry, phase) for entry in self.entries if getattr(entry, phase) > 0]
            
            if values:
                stats[phase] = {
                    'count': len(values),
                    'total': sum(values),
                    'average': mean(values),
                    'median': median(values),
                    'min': min(values),
                    'max': max(values),
                    'std_dev': stdev(values) if len(values) > 1 else 0.0
                }
            else:
                stats[phase] = {
                    'count': 0,
                    'total': 0,
                    'average': 0,
                    'median': 0,
                    'min': 0,
                    'max': 0,
                    'std_dev': 0
                }
        
        return stats
    
    def get_slowest_requests(self, n: int = 10) -> List[TimingInfo]:
        """Return the N slowest requests by total time"""
        sorted_entries = sorted(self.entries, key=lambda x: x.total_time, reverse=True)
        return sorted_entries[:n]
    
    def get_requests_by_status(self) -> Dict[int, int]:
        """Count requests grouped by HTTP status code"""
        status_counts = {}
        for entry in self.entries:
            status_counts[entry.status] = status_counts.get(entry.status, 0) + 1
        return dict(sorted(status_counts.items()))
    
    def print_summary(self) -> None:
        """Print a summary of the analysis"""
        print(f"\n{'='*80}")
        print(f"HAR File Analysis Summary")
        print(f"{'='*80}")
        print(f"File: {self.har_file_path}")
        print(f"Total Requests: {len(self.entries)}")
        print(f"{'='*80}\n")
        
        # Status code distribution
        print("HTTP Status Code Distribution:")
        print("-" * 40)
        status_counts = self.get_requests_by_status()
        for status, count in status_counts.items():
            print(f"  {status}: {count} requests")
        print()
        
        # Timing statistics
        stats = self.calculate_statistics()
        
        print("Timing Statistics (all times in milliseconds):")
        print("-" * 80)
        print(f"{'Phase':<15} {'Count':>8} {'Average':>12} {'Median':>12} {'Min':>12} {'Max':>12}")
        print("-" * 80)
        
        phase_names = {
            'total_time': 'Total Time',
            'blocked': 'Blocked',
            'dns': 'DNS Lookup',
            'connect': 'TCP Connect',
            'send': 'Send Request',
            'wait': 'Wait (TTFB)',
            'receive': 'Download',
            'ssl': 'SSL/TLS'
        }
        
        for phase, name in phase_names.items():
            if phase in stats:
                s = stats[phase]
                print(f"{name:<15} {s['count']:>8} {s['average']:>12.2f} {s['median']:>12.2f} "
                      f"{s['min']:>12.2f} {s['max']:>12.2f}")
        
        print()
        
        # Slowest requests
        print("Top 10 Slowest Requests:")
        print("-" * 80)
        slowest = self.get_slowest_requests(10)
        for i, entry in enumerate(slowest, 1):
            # Truncate URL if too long
            url = entry.url if len(entry.url) <= 60 else entry.url[:57] + "..."
            print(f"{i:2}. [{entry.status}] {entry.total_time:>8.2f}ms - {entry.method} {url}")
        
        print(f"\n{'='*80}\n")
    
    def export_to_json(self, output_file: str) -> None:
        """Export analysis results to JSON file"""
        stats = self.calculate_statistics()
        slowest = self.get_slowest_requests(10)
        status_counts = self.get_requests_by_status()
        
        output_data = {
            'summary': {
                'source_file': str(self.har_file_path),
                'total_requests': len(self.entries),
                'status_distribution': status_counts
            },
            'timing_statistics': stats,
            'slowest_requests': [
                {
                    'url': entry.url,
                    'method': entry.method,
                    'status': entry.status,
                    'total_time_ms': entry.total_time
                }
                for entry in slowest
            ]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"Analysis exported to: {output_file}")


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python har_analyzer.py <har_file_path> [--export <output.json>]")
        print("\nExample:")
        print("  python har_analyzer.py mywebsite.har")
        print("  python har_analyzer.py mywebsite.har --export results.json")
        sys.exit(1)
    
    har_file = sys.argv[1]
    export_file = None
    
    # Check for export flag
    if len(sys.argv) >= 4 and sys.argv[2] == '--export':
        export_file = sys.argv[3]
    
    # Create analyzer and run analysis
    analyzer = HARAnalyzer(har_file)
    analyzer.extract_timings()
    analyzer.print_summary()
    
    # Export if requested
    if export_file:
        analyzer.export_to_json(export_file)


if __name__ == '__main__':
    main()

