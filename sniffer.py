import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, PcapWriter
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from datetime import datetime
import argparse
import socket
import os
import json
from collections import defaultdict, OrderedDict
import ipaddress
import queue
import geoip2.database
import netifaces
import platform

MAX_CACHE_SIZE = 1000
MAX_PACKETS_STORED = 50
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output')
GEOIP_DIR = os.path.join(os.path.dirname(__file__), 'geoip')
EXPORT_FILE = os.path.join(OUTPUT_DIR, 'network_stats.json')
PCAP_FILE = os.path.join(OUTPUT_DIR, 'network_capture.pcap')
GEOIP_DATABASE = os.path.join(GEOIP_DIR, 'GeoLite2-City.mmdb')

console = Console()
data_lock = threading.Lock()
packets_info = []
protocol_counts = defaultdict(int)
country_counts = defaultdict(int)
total_packets = 0
total_bytes = 0
start_time = None
local_ip = None
geoip_cache = OrderedDict()
capture_active = False
packet_queue = queue.Queue()
pcap_writer = None

_reader = None
_reader_lock = threading.Lock()

def _get_reader():
    global _reader
    with _reader_lock:
        if _reader is None:
            if not os.path.isfile(GEOIP_DATABASE):
                console.print(f"[bold red]Error: GeoIP database file {GEOIP_DATABASE} not found.[/] "
                              "Please place GeoLite2-City.mmdb in the GeoIP directory. "
                              "Download from https://www.maxmind.com.")
                raise SystemExit
            try:
                _reader = geoip2.database.Reader(GEOIP_DATABASE)
            except Exception as e:
                console.print(f"[bold red]Error: Failed to load GeoIP database {GEOIP_DATABASE}: {e}[/]")
                raise SystemExit
        return _reader

protocol_colors = {
    "TCP": "blue",
    "UDP": "green",
    "ICMP": "yellow",
    "ARP": "magenta",
    "DNS": "cyan",
    "HTTP": "red",
    "HTTPS": "bright_red",
    "IPv6": "purple"
}

def setup_directories():
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs(GEOIP_DIR, exist_ok=True)
    except Exception as e:
        console.print(f"[bold red]Error: Failed to create directories: {e}[/]")
        raise SystemExit

def clear_previous_data():
    try:
        if os.path.exists(EXPORT_FILE):
            os.remove(EXPORT_FILE)
        if os.path.exists(PCAP_FILE):
            os.remove(PCAP_FILE)
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to clear previous data: {e}[/]")

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return True

def lookup_geoip(ip):
    if ip in geoip_cache:
        geoip_cache.move_to_end(ip)
        return geoip_cache[ip]
    
    if is_private_ip(ip):
        location = "Local/Private"
    else:
        try:
            reader = _get_reader()
            resp = reader.city(ip)
            country = resp.country.name or "Unknown"
            region = resp.subdivisions.most_specific.name or ""
            city = resp.city.name or ""
            location_parts = [part for part in [city, region, country] if part]
            location = ', '.join(location_parts[:2]) or country or "Unknown"
        except geoip2.errors.AddressNotFoundError:
            location = "Unknown"
        except geoip2.errors.GeoIP2Error as e:
            location = "GeoIP Error"
        except Exception as e:
            location = "Lookup Failed"
    
    geoip_cache[ip] = location
    geoip_cache.move_to_end(ip)
    if len(geoip_cache) > MAX_CACHE_SIZE:
        geoip_cache.popitem(last=False)
    return location

def extract_country_from_location(location):
    if not location:
        return "Unknown"
    
    if location in ["Unknown", "GeoIP Error", "Lookup Failed"]:
        return location
    
    if any(term in location.lower() for term in ["local", "private", "machine"]):
        return None
    
    if ',' in location:
        parts = [part.strip() for part in location.split(',')]
        country = parts[-1]
        if country:
            return country
        elif len(parts) > 1:
            country = parts[-2] if len(parts) >= 2 else parts[0]
            return country
    
    return location

def get_service_info(pkt):
    service = "Unknown"
    if TCP in pkt:
        port = pkt[TCP].dport or pkt[TCP].sport
        if port:
            service_map = {
                80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                25: "SMTP", 110: "POP3", 143: "IMAP", 993: "IMAPS",
                995: "POP3S", 53: "DNS", 23: "Telnet", 3389: "RDP"
            }
            service = service_map.get(port, f"TCP:{port}")
    elif UDP in pkt:
        port = pkt[UDP].dport or pkt[UDP].sport
        if port:
            service = {
                53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP"
            }.get(port, f"UDP:{port}")
    return service

async def enrich_packet_async(pkt, executor):
    global total_packets, total_bytes, pcap_writer
    
    try:
        src_ip = None
        dst_ip = None
        proto = "Unknown"
        
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if TCP in pkt:
                proto = get_service_info(pkt) if get_service_info(pkt) in ["HTTP", "HTTPS", "DNS"] else "TCP"
            elif UDP in pkt:
                proto = "DNS" if get_service_info(pkt) == "DNS" else "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            proto = "IPv6"
            if TCP in pkt:
                proto = get_service_info(pkt) if get_service_info(pkt) in ["HTTP", "HTTPS", "DNS"] else "TCP"
            elif UDP in pkt:
                proto = "DNS" if get_service_info(pkt) == "DNS" else "UDP"
            elif ICMP in pkt:
                proto = "ICMPv6"
        elif ARP in pkt:
            proto = "ARP"
            src_ip = pkt[ARP].psrc if hasattr(pkt[ARP], 'psrc') else None
            dst_ip = pkt[ARP].pdst if hasattr(pkt[ARP], 'pdst') else None
        else:
            return
        
        if not src_ip or not dst_ip:
            return
        
        pkt_time = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pkt_len = len(pkt)
        
        with data_lock:
            if pcap_writer is not None:
                try:
                    pcap_writer.write(pkt)
                except Exception as e:
                    console.print(f"[bold yellow]Warning: Failed to write to pcap file: {e}[/]")
        
        loop = asyncio.get_event_loop()
        try:
            src_loc = await loop.run_in_executor(executor, lookup_geoip, src_ip)
            dst_loc = await loop.run_in_executor(executor, lookup_geoip, dst_ip)
        except geoip2.errors.GeoIP2Error as e:
            console.print(f"[bold yellow]Warning: GeoIP lookup failed: {e}[/]")
            src_loc = dst_loc = "GeoIP Error"
        
        if local_ip and (src_ip == local_ip or dst_ip == local_ip):
            src_loc = "Local Machine" if src_ip == local_ip else src_loc
            dst_loc = "Local Machine" if dst_ip == local_ip else dst_loc
        
        pkt_info = {
            "time": pkt_time,
            "src": str(src_ip),
            "src_loc": str(src_loc),
            "dst": str(dst_ip),
            "dst_loc": str(dst_loc),
            "proto": proto,
            "len": pkt_len,
            "direction": "OUT" if src_ip == local_ip else "IN" if dst_ip == local_ip else "FWD"
        }
        
        with data_lock:
            packets_info.append(pkt_info)
            if len(packets_info) > MAX_PACKETS_STORED:
                packets_info.pop(0)
            
            protocol_counts[proto] += 1
            total_packets += 1
            total_bytes += pkt_len
            
            for loc in [src_loc, dst_loc]:
                country = extract_country_from_location(loc)
                if country:
                    country_counts[country] += 1
        
    except Exception as e:
        console.print(f"[bold yellow]Warning: Error processing packet: {e}[/]")

def build_header_panel():
    if not start_time:
        return Panel(
            Align.center("[bold bright_cyan]NETWORK TRAFFIC MONITOR[/] [dim]- Initializing...[/]"),
            # style="bold white on blue",
            border_style="bright_blue"
        )
        
    duration = datetime.now() - start_time
    duration_seconds = duration.total_seconds()
    with data_lock:
        packets = total_packets
        protocols = len(protocol_counts)
        locations = len(country_counts)
        bytes_transferred = total_bytes
        packet_rate = packets / duration_seconds if duration_seconds > 0 else 0
    
    status = "ACTIVE" if capture_active else "STOPPED"
    interface_name = getattr(args, 'interface', 'Unknown')
    filter_str = getattr(args, 'filter', None) or 'All Traffic'
    
    duration_str = f"{int(duration_seconds // 60):02d}:{int(duration_seconds % 60):02d}"
    bytes_str = f"{bytes_transferred / 1024:.1f} KB" if bytes_transferred < 1024*1024 else f"{bytes_transferred / (1024*1024):.1f} MB"
    
    table = Table(
        show_header=False,
        expand=True,
        show_lines=False,
        padding=0,
        border_style="bright_blue"
    )
    table.add_column(justify="left", width=30)
    table.add_column(justify="left", width=30)
    table.add_column(justify="left", width=30)
    
    table.add_row(
        f"[bold]Status:[/] [orange1]{status}[/]",
        f"[bold]Packets:[/] [orange1]{packets:,}[/]",
        f"[bold]Data:[/] [orange1]{bytes_str}[/]"
    )
    table.add_row(
        f"[bold]Filter:[/] [orange1]{filter_str}[/]",
        f"[bold]Protocols:[/] [orange1]{protocols}[/]",
        f"[bold]Runtime:[/] [orange1]{duration_str}[/]"
    )
    table.add_row(
        f"[bold]Interface:[/] [orange1]{interface_name}[/]",
        f"[bold]Locations:[/] [orange1]{locations}[/]",
        f"[bold]Packet Rate:[/] [orange1]{packet_rate:.1f} p/s[/]"
    )
    
    try:
        return Panel(
            Align.center(table),
            title="[bold bright_cyan]NETWORK TRAFFIC ANALYZER[/] [dim]v1.0[/]",
            subtitle="[dim]Developed by Gidne Huda[/]",
            # style="bold white on black",
            border_style="bright_blue",
            padding=(1, 2)
        )
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to render header panel: {e}. Using default style.[/]")
        return Panel(
            Align.center(table),
            title="NETWORK TRAFFIC ANALYZER v1.0",
            subtitle="Developed by Gidne Huda",
            style="bold white on black",
            border_style="white",
            padding=(1, 2)
        )

def build_packet_table():
    table = Table(
        title="Live Packet Stream",
        show_header=True,
        header_style="bright_cyan",
        expand=True,
        show_lines=False,
        title_style="bold bright_yellow",
    )
    
    table.add_column("Time", style="dim", no_wrap=True, width=12)
    table.add_column("Direction", justify="center", width=10)
    table.add_column("Source IP", width=15)
    table.add_column("Source Location", style="green")
    table.add_column("Destination IP", width=15)
    table.add_column("Destination Location", style="green")
    table.add_column("Protocol", justify="center", width=8)
    table.add_column("Size", justify="right", width=8)
    
    with data_lock:
        for p in packets_info:
            proto_style = protocol_colors.get(p['proto'], "white")
            term_width = console.size.width
            max_loc_width = max(15, (term_width - 80) // 2)
            src_loc = p['src_loc'][:max_loc_width-2] + ".." if len(p['src_loc']) > max_loc_width else p['src_loc']
            dst_loc = p['dst_loc'][:max_loc_width-2] + ".." if len(p['dst_loc']) > max_loc_width else p['dst_loc']
            
            direction_map = {
                "IN": "Incoming",
                "OUT": "Outgoing", 
                "FWD": "Forwarding"
            }
            direction_full = direction_map.get(p['direction'], p['direction'])
            
            if p['direction'] == "IN":
                direction_style = "green"
            elif p['direction'] == "OUT":
                direction_style = "blue"
            else:
                direction_style = "yellow"
            
            table.add_row(
                p['time'],
                Text(direction_full, style=direction_style),
                p['src'],
                src_loc,
                p['dst'],
                dst_loc,
                Text(p['proto'], style=proto_style),
                f"{p['len']:,}B"
            )
    
    try:
        return Panel(table, padding=(1, 1), border_style="bold bright_yellow")
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to render packet table: {e}. Using default style.[/]")
        return Panel(table, padding=(1, 1), border_style="bold bright_yellow")

def build_protocol_stats():
    table = Table(
        title="Protocol Distribution",
        show_header=True,
        expand=True,
        show_lines=False,
        title_style="bold bright_red"
    )
    table.add_column("Protocol", style="bold", width=12)
    table.add_column("Count", justify="right", width=10)
    table.add_column("Percentage", justify="right", width=10)
    table.add_column("Chart", width=20)
    
    with data_lock:
        total = sum(protocol_counts.values())
        if total == 0:
            table.add_row("No data", "0", "0.0%", "")
            return Panel(table, padding=(1, 1), border_style="bold bright_red")
            
        sorted_protocols = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)
        for proto, count in sorted_protocols:
            pct = (count / total) * 100
            bar_length = max(1, min(int(pct * 0.3 + 1), 15))
            bar = "█" * bar_length
            proto_style = protocol_colors.get(proto, "white")
            table.add_row(
                Text(proto, style=proto_style),
                f"{count:,}",
                f"{pct:.1f}%",
                Text(bar, style=proto_style)
            )
    
    try:
        return Panel(table, padding=(1, 1), border_style="bold bright_red")
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to render protocol stats: {e}. Using default style.[/]")
        return Panel(table, padding=(1, 1), border_style="bold bright_red")

def build_geo_stats():
    table = Table(
        title="Geographic Distribution",
        show_header=True,
        expand=True,
        show_lines=False,
        title_style="bold bright_green"
    )
    table.add_column("Country/Region", style="bold", width=20)
    table.add_column("Packets", justify="right", width=10)
    table.add_column("Chart", width=20)
    
    with data_lock:
        if not country_counts:
            table.add_row("No geographic data", "0", "")
            table.add_row("Check network or GeoIP DB", "", "")
            return Panel(table, padding=(1, 1), border_style="bold bright_green")
            
        total = sum(country_counts.values())
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        for country, count in sorted_countries:
            pct = (count / total) * 100
            bar_length = max(1, min(int(pct * 0.4 + 1), 15))
            bar = "█" * bar_length
            country_display = country[:18] if len(country) > 18 else country
            table.add_row(
                country_display,
                f"{count:,}",
                Text(bar, style="green")
            )
    
    try:
        return Panel(table, padding=(1, 1), border_style="bold bright_green")
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to render geo stats: {e}. Using default style.[/]")
        return Panel(table, padding=(1, 1), border_style="bold bright_green")

def generate_layout():
    layout = Layout()
    try:
        layout.split_column(
            Layout(build_header_panel(), name="header", size=8),
            Layout(build_packet_table(), name="packets"),
            Layout(name="stats", size=20)
        )
        layout["stats"].split_row(
            Layout(build_protocol_stats(), name="protocols"),
            Layout(build_geo_stats(), name="geography")
        )
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to generate layout: {e}. Using simplified layout.[/]")
        layout = Layout()
        layout.split_column(
            Layout(build_header_panel(), name="header", size=8),
            Layout(build_packet_table(), name="packets")
        )
    return layout

def validate_bpf_filter(filter_str):
    try:
        from scapy.all import Ether
        sniff(filter=filter_str, count=0, store=False, prn=lambda x: None, timeout=0)
        return True
    except Exception as e:
        console.print(f"[bold red]Invalid BPF filter: {filter_str} - {e}[/]")
        return False

def export_stats():
    with data_lock:
        stats = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_counts": dict(protocol_counts),
            "country_counts": dict(country_counts),
            "timestamp": datetime.now().isoformat()
        }
    try:
        with open(EXPORT_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to export stats: {e}[/]")

def capture_packets():
    global capture_active, pcap_writer
    try:
        capture_active = True
        with data_lock:
            pcap_writer = PcapWriter(PCAP_FILE, append=False, sync=True)
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: packet_queue.put(pkt),
            store=0,
            stop_filter=lambda x: not capture_active
        )
    except PermissionError:
        console.print("[bold red]Permission denied. Try running with sudo.[/]")
    except OSError as e:
        console.print(f"[bold red]Network interface error: {e}[/]")
    except Exception as e:
        console.print(f"[bold red]Capture error: {e}[/]")
    finally:
        capture_active = False
        with data_lock:
            if pcap_writer is not None:
                try:
                    pcap_writer.close()
                except Exception as e:
                    console.print(f"[bold yellow]Warning: Error closing pcap file: {e}[/]")
                pcap_writer = None

async def process_packet_queue(executor):
    while capture_active or not packet_queue.empty():
        try:
            pkt = await asyncio.get_event_loop().run_in_executor(None, packet_queue.get)
            await enrich_packet_async(pkt, executor)
            packet_queue.task_done()
        except Exception as e:
            console.print(f"[bold yellow]Warning: Error in packet queue processing: {e}[/]")
            await asyncio.sleep(0.1)

def get_local_ip(interface):
    try:
        for iface in netifaces.interfaces():
            if iface == interface:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to detect local IP: {e}, defaulting to 127.0.0.1[/]")
        return "127.0.0.1"

def display_final_message():
    table = Table(
        title="Network Capture Completed",
        show_header=True,
        header_style="bold green",
        expand=True,
        show_lines=True,
        border_style="bright_green"
    )
    table.add_column("File", style="bold", width=30)
    table.add_column("Description", style="bold")
    
    table.add_row(
        f"Output/{os.path.basename(EXPORT_FILE)}",
        "Contains aggregated network statistics in JSON format, including total packets, bytes, "
        "protocol distribution, and geographic distribution."
    )
    table.add_row(
        f"Output/{os.path.basename(PCAP_FILE)}",
        "A PCAP file containing raw packet data for detailed, low-level analysis using tools "
        "like Wireshark or tcpdump."
    )
    
    try:
        console.print(Panel(
            table,
            title="[bold bright_cyan]NETWORK TRAFFIC ANALYZER[/] [dim]v1.0[/]",
            subtitle="[dim]Developed by Gidne Huda for CodeAlpha Cybersecurity Internship[/]",
            border_style="bright_cyan",
            padding=(1, 1)
        ))
    except Exception as e:
        console.print(f"[bold yellow]Warning: Failed to render final message: {e}. Displaying plain table.[/]")
        console.print(table)

async def main():
    global start_time, args, local_ip, capture_active
    
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitor with Geographic Intelligence\n"
                    "Developed by Gidne Huda as part of the CodeAlpha Cybersecurity Internship\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 network_sniffer.py -i eth0                    # Monitor all traffic
  sudo python3 network_sniffer.py -i wlan0 -f "tcp port 80"  # Monitor HTTP traffic
  sudo python3 network_sniffer.py -i any -f "not port 22"    # Exclude SSH traffic
        """
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface (eth0, wlan0, any)")
    parser.add_argument("-f", "--filter", help="BPF filter expression")
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    setup_directories()
    
    if platform.system() != 'Windows':
        try:
            if os.geteuid() != 0:
                console.print("[bold yellow]Warning: Root privileges recommended for packet capture[/]")
                console.print("Try: [bold]sudo python3 network_sniffer.py -i <interface>[/]\n")
        except AttributeError:
            pass
    
    if args.filter and not validate_bpf_filter(args.filter):
        console.print("[bold red]Invalid BPF filter provided. Exiting.[/]")
        return
    
    clear_previous_data()
    
    local_ip = get_local_ip(args.interface)
    start_time = datetime.now()
    
    console.print(f"[bold blue]Starting capture on interface:[/] {args.interface}")
    if args.filter:
        console.print(f"[bold cyan]Filter applied:[/] {args.filter}")
    console.print("\n[dim]Press Ctrl+C to stop...[/]\n")
    
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        asyncio.create_task(process_packet_queue(executor))
        try:
            with Live(generate_layout(), refresh_per_second=1, screen=True) as live:
                while True:
                    live.update(generate_layout())
                    await asyncio.sleep(1.0)
        except (KeyboardInterrupt, asyncio.exceptions.CancelledError):
            capture_active = False
            while not capture_active and not packet_queue.empty():
                await asyncio.sleep(0.1)
            export_stats()
            display_final_message()
        except Exception as e:
            console.print(f"\n[bold red]Unexpected error: {e}[/]")
        finally:
            console.print("[bold green]Sniffer stopped successfully.[/]")
            if _reader is not None:
                _reader.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.exceptions.CancelledError):
        pass
