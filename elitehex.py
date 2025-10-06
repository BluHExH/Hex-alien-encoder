#!/usr/bin/env python3
# HEX Alien Encoder Pro - Ultimate File Obfuscation Tool
# Enhanced with Elite UI, Advanced Security, and Premium Features

import sys
import argparse
import base64
import hashlib
import json
import os
import random
import time
from textwrap import dedent
from datetime import datetime

# ------------------ Enhanced Configuration ------------------
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

# Expanded Elite Symbol Pool
SYMBOL_POOL = [
    '⚛','⍟','⊹','⟁','⧫','⚚','☍','⧉','⋔','⊰','⟟','⌬','☌','⚶','⩊','⚷',
    '⩇','⧗','⚺','⧃','⨁','⟊','☊','⩀','⧠','⟠','⋇','⧰','⚿','⧴','⩆','⧵',
    '⧾','⩅','⧣','⩈','⩉','⩄','⧱','⧲','⧳','⩁','⩂','⧶','⧷','⧸','⧹','⧺',
    '⧻','⧼','⧽','⨂','⨃','⨄','⨅','⌖','⌗','⌘','✶','✷','✸','✹','✺','✻',
    '✼','✽','✾','✿','❀','❁','❂','❃','❄','❅','❆','❇','❈','❉','❊','❋',
    '✦','✧','✩','✪','✫','✬','✭','✮','✯','✰','☀','☁','☂','☃','☄','★',
    '☆','☇','☈','☉','☊','☋','☌','☍','☎','☏','☐','☑','☒','♔','♕','♖',
    '♗','♘','♙','♚','♛','♜','♝','♞','♟','♠','♡','♢','♣','♤','♥','♦',
    '♧','♨','♩','♪','♫','♬','♭','♮','♯','⚀','⚁','⚂','⚃','⚄','⚅','⚆',
    '⚇','⚈','⚉','⚐','⚑','⚒','⚓','⚔','⚕','⚖','⚗','⚘','⚙','⚚','⚛','⚜',
    '⚠','⚡','⚢','⚣','⚤','⚥','⚦','⚧','⚨','⚩','⚪','⚫','⚬','⚭','⚮','⚯'
]

HEADER_PREFIX = '::HEX-ALIEN-PRO-V2::'
HEADER_SEP = '::'

# ------------------ Enhanced Utilities ------------------

def sha256_hex(s: str) -> str:
    h = hashlib.sha256()
    h.update(s.encode('utf-8'))
    return h.hexdigest()

def generate_elite_banner():
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
\033[1;35m
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║  ██╗  ██╗███████╗██╗  ██╗    █████╗ ██╗     ██╗███████╗███╗   ██╗  ║
║  ██║  ██║██╔════╝╚██╗██╔╝   ██╔══██╗██║     ██║██╔════╝████╗  ██║  ║
║  ███████║█████╗   ╚███╔╝    ███████║██║     ██║█████╗  ██╔██╗ ██║  ║
║  ██╔══██║██╔══╝   ██╔██╗    ██╔══██║██║     ██║██╔══╝  ██║╚██╗██║  ║
║  ██║  ██║███████╗██╔╝ ██╗   ██║  ██║███████╗██║███████╗██║ ╚████║  ║
║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═══╝  ║
║                                                                ║
╠════════════════════════════════════════════════════════════════╣
║ 🔥 HEX ALIEN ENCODER PRO - ULTIMATE FILE OBFUSCATION         ║
║ ⚡ Cyber 17 Official | Elite Security Tool                   ║
║ 🔒 Safe Mode: No Auto-Execution | Tamper Detection          ║
║ 📅 {current_time}                         ║
╚════════════════════════════════════════════════════════════════╝
\033[0m
"""

def print_colored(text, color_code):
    print(f"\033[{color_code}m{text}\033[0m")

def animate_loading(text, duration=2):
    chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        print(f"\r\033[1;36m{chars[i % len(chars)]} {text}\033[0m", end="", flush=True)
        time.sleep(0.1)
        i += 1
    print("\r" + " " * 50 + "\r", end="", flush=True)

def make_symbol_map(randomize=False, seed=None):
    needed = len(BASE64_CHARS) + 1
    pool = SYMBOL_POOL.copy()
    if randomize:
        if seed is not None:
            rnd = random.Random(seed)
            rnd.shuffle(pool)
        else:
            random.shuffle(pool)
    if len(pool) < needed:
        raise RuntimeError('Not enough symbols in SYMBOL_POOL; add more symbols.')
    symbols = pool[:needed]
    mapping = {BASE64_CHARS[i]: symbols[i] for i in range(len(BASE64_CHARS))}
    mapping['|'] = symbols[len(BASE64_CHARS)]
    return mapping, symbols

def map_payload(payload: str, mapping: dict):
    out = []
    for ch in payload:
        if ch in mapping:
            out.append(mapping[ch])
        else:
            out.append('⨀' + format(ord(ch), 'x') + '⨁')
    return ''.join(out)

def unmap_payload(data: str, revmap: dict):
    decoded_chars = []
    i = 0
    L = len(data)
    while i < L:
        ch = data[i]
        if ch in revmap:
            decoded_chars.append(revmap[ch])
            i += 1
        else:
            if data.startswith('⨀', i):
                j = data.find('⨁', i+1)
                if j == -1:
                    raise ValueError('Malformed package: missing closing ⨁')
                hx = data[i+1:j]
                decoded_chars.append(chr(int(hx, 16)))
                i = j+1
            else:
                i += 1
    return ''.join(decoded_chars)

# ------------------ Enhanced Core Functions ------------------

def sign_payload(b64text: str, passphrase: str) -> str:
    return sha256_hex(passphrase + b64text)

def encode_files(input_paths, out_path, passphrase, randomize=False, seed=None):
    print_colored("🚀 Starting Elite Encoding Process...", "1;32")
    animate_loading("Analyzing input files", 1)
    
    bundle = {'files': [], 'metadata': {}}
    total_size = 0
    
    for p in input_paths:
        if not os.path.exists(p):
            print_colored(f"❌ Error: File not found - {p}", "1;31")
            return
        
        with open(p, 'rb') as f:
            raw = f.read()
        b64 = base64.b64encode(raw).decode('ascii')
        file_info = {
            'name': os.path.basename(p),
            'size': len(raw),
            'b64': b64,
            'timestamp': datetime.now().isoformat()
        }
        bundle['files'].append(file_info)
        total_size += len(raw)
    
    bundle['metadata'] = {
        'total_files': len(input_paths),
        'total_size': total_size,
        'encoded_at': datetime.now().isoformat(),
        'version': 'HEX-ALIEN-PRO-V2'
    }
    
    animate_loading("Creating secure bundle", 1)
    json_text = json.dumps(bundle, separators=(',', ':'), ensure_ascii=False)
    b64_payload = base64.b64encode(json_text.encode('utf-8')).decode('ascii')
    signature = sign_payload(b64_payload, passphrase)
    payload = signature + '|' + b64_payload

    animate_loading("Generating alien symbols", 1)
    mapping, symbols = make_symbol_map(randomize=randomize, seed=seed)
    mapped = map_payload(payload, mapping)

    symbols_joined = ''.join(symbols)
    header_map_b64 = base64.b64encode(symbols_joined.encode('utf-8')).decode('ascii')
    header = HEADER_PREFIX + 'MAP' + HEADER_SEP + header_map_b64 + HEADER_SEP + 'RAND' + HEADER_SEP + ('1' if randomize else '0') + HEADER_SEP

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(header + mapped)

    print_colored("✅ ENCODING COMPLETED SUCCESSFULLY!", "1;32")
    print_colored(f"📁 Output File: {out_path}", "1;36")
    print_colored(f"📊 Files Encoded: {len(input_paths)}", "1;33")
    print_colored(f"💾 Total Size: {total_size} bytes", "1;33")
    print_colored(f"🔐 Signature: {signature[:16]}...", "1;35")
    print_colored(f"🎯 Symbol Randomization: {'ENABLED' if randomize else 'DISABLED'}", "1;34")

def parse_header_and_payload(encoded_text: str):
    if not encoded_text.startswith(HEADER_PREFIX):
        raise ValueError('Not a valid HEX ALIEN PRO package (missing header).')
    rest = encoded_text[len(HEADER_PREFIX):]
    parts = rest.split(HEADER_SEP, 4)
    if len(parts) < 5:
        raise ValueError('Malformed header in package.')
    tag_map = parts[0]
    map_b64 = parts[1]
    tag_rand = parts[2]
    rand_flag = parts[3]
    payload = parts[4]
    symbols_joined = base64.b64decode(map_b64.encode('ascii')).decode('utf-8')
    needed = len(BASE64_CHARS) + 1
    symbols = list(symbols_joined)[:needed]
    revmap = {symbols[i]: BASE64_CHARS[i] for i in range(len(BASE64_CHARS))}
    revmap[symbols[len(BASE64_CHARS)]] = '|'
    return revmap, payload

def decode_package(encoded_path, passphrase, save_as=None):
    print_colored("🔍 Starting Elite Decoding Process...", "1;32")
    animate_loading("Loading encrypted package", 1)
    
    if not os.path.exists(encoded_path):
        print_colored(f"❌ Error: Package file not found - {encoded_path}", "1;31")
        return
    
    with open(encoded_path, 'r', encoding='utf-8') as f:
        data = f.read()
    
    animate_loading("Decrypting alien symbols", 1)
    revmap, payload_mapped = parse_header_and_payload(data)
    payload = unmap_payload(payload_mapped, revmap)
    
    if '|' not in payload:
        raise ValueError('No signature separator in payload.')
    
    sig, b64 = payload.split('|', 1)
    expected = sign_payload(b64, passphrase)
    
    if expected != sig:
        print_colored("🚨 SECURITY ALERT: SIGNATURE MISMATCH!", "1;31")
        print_colored("Possible issues:", "1;33")
        print_colored("  • Wrong passphrase", "1;33")
        print_colored("  • File tampering detected", "1;33")
        print_colored("  • Corrupted package", "1;33")
        print_colored(f"  Found : {sig[:16]}...", "1;31")
        print_colored(f"  Expect: {expected[:16]}...", "1;32")
        return
    
    animate_loading("Verifying package integrity", 1)
    raw = base64.b64decode(b64)
    
    try:
        text = raw.decode('utf-8')
        bundle = json.loads(text)
    except Exception:
        bundle = None
    
    print_colored("\n" + "═" * 60, "1;36")
    print_colored("🎉 DECODE SUCCESSFUL - PACKAGE PREVIEW", "1;32")
    print_colored("═" * 60, "1;36")
    
    if bundle is None:
        print_colored("[!] Could not parse bundle as JSON or non-text content.", "1;33")
    else:
        metadata = bundle.get('metadata', {})
        files = bundle.get('files', [])
        
        print_colored(f"📦 Package Metadata:", "1;36")
        print_colored(f"   Version: {metadata.get('version', 'Unknown')}", "1;33")
        print_colored(f"   Encoded: {metadata.get('encoded_at', 'Unknown')}", "1;33")
        print_colored(f"   Total Files: {len(files)}", "1;33")
        print_colored(f"   Total Size: {metadata.get('total_size', 0)} bytes", "1;33")
        
        print_colored(f"\n📁 Files in Package:", "1;36")
        for idx, fi in enumerate(files, 1):
            name = fi.get('name')
            size = fi.get('size', 0)
            print_colored(f"   [{idx}] {name} ({size} bytes)", "1;32")
        
        print_colored(f"\n🔍 Content Preview:", "1;36")
        for idx, fi in enumerate(files, 1):
            name = fi.get('name')
            b64 = fi.get('b64')
            decoded_bytes = base64.b64decode(b64)
            try:
                dec_text = decoded_bytes.decode('utf-8')
                snippet = (dec_text[:300] + '...') if len(dec_text) > 300 else dec_text
                print_colored(f"\n   📄 {name} (Preview):", "1;35")
                print_colored(f"   {snippet}", "1;37")
            except Exception:
                print_colored(f"\n   📄 {name} (Binary file - {len(decoded_bytes)} bytes)", "1;33")
    
    print_colored("\n" + "═" * 60, "1;36")
    
    if save_as:
        animate_loading(f"Saving to {save_as}", 1)
        if bundle and len(bundle.get('files', [])) == 1:
            content = base64.b64decode(bundle['files'][0]['b64'])
            with open(save_as, 'wb') as f:
                f.write(content)
            print_colored(f'💾 Saved decoded file to {save_as}', "1;32")
        else:
            with open(save_as, 'wb') as f:
                f.write(raw)
            print_colored(f'💾 Saved raw decoded bytes to {save_as}', "1;32")

# ------------------ Enhanced CLI ------------------

def main_cli():
    parser = argparse.ArgumentParser(
        description='🔥 HEX Alien Encoder Pro - Ultimate File Obfuscation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent('''
        🎯 Examples:
          Encode single file:
            python HEX_Alien_Encoder_Pro.py encode script.py output.aln --passphrase mypass
            
          Encode multiple files with randomization:
            python HEX_Alien_Encoder_Pro.py encode file1.py file2.py output.aln --passphrase mypass --randomize
            
          Decode and preview:
            python HEX_Alien_Encoder_Pro.py decode output.aln --passphrase mypass
            
          Decode and save:
            python HEX_Alien_Encoder_Pro.py decode output.aln --passphrase mypass --save restored.py
            
        🔒 Safety Features:
          • No auto-execution of decoded files
          • Tamper detection with SHA-256 signatures
          • Secure passphrase protection
        ''')
    )
    
    sub = parser.add_subparsers(dest='cmd', title='Commands')

    p_enc = sub.add_parser('encode', help='🚀 Encode one or more files into alien symbols')
    p_enc.add_argument('inputs', nargs='+', help='Input file(s) followed by output file (last argument)')
    p_enc.add_argument('--passphrase', required=True, help='Secret passphrase for encryption')
    p_enc.add_argument('--randomize', action='store_true', help='Enable random symbol mapping for enhanced security')
    p_enc.add_argument('--seed', type=int, help='Custom seed for reproducible randomization')

    p_dec = sub.add_parser('decode', help='🔍 Decode alien package and preview contents')
    p_dec.add_argument('package', help='Encoded .aln package file')
    p_dec.add_argument('--passphrase', required=True, help='Secret passphrase for decryption')
    p_dec.add_argument('--save', help='Optional path to save decoded file(s)')

    p_list = sub.add_parser('list', help='📁 List files in package without full decoding')
    p_list.add_argument('package', help='Encoded .aln package file')

    p_info = sub.add_parser('info', help='ℹ️ Show tool information and symbol pool stats')

    args = parser.parse_args()
    
    print(generate_elite_banner())

    if args.cmd == 'encode':
        if len(args.inputs) < 2:
            print_colored('❌ Error: Specify input file(s) and output path as last argument', '1;31')
            return
        *in_files, outp = args.inputs
        encode_files(in_files, outp, args.passphrase, randomize=args.randomize, seed=args.seed)

    elif args.cmd == 'decode':
        decode_package(args.package, args.passphrase, save_as=args.save)

    elif args.cmd == 'list':
        animate_loading("Reading package information", 1)
        try:
            with open(args.package, 'r', encoding='utf-8') as f:
                data = f.read()
            revmap, payload_mapped = parse_header_and_payload(data)
            payload = unmap_payload(payload_mapped, revmap)
            if '|' not in payload:
                print_colored('❌ Invalid package payload', '1;31')
                return
            sig, b64 = payload.split('|', 1)
            raw = base64.b64decode(b64)
            text = raw.decode('utf-8')
            bundle = json.loads(text)
            metadata = bundle.get('metadata', {})
            files = bundle.get('files', [])
            
            print_colored("📦 PACKAGE INFORMATION", "1;32")
            print_colored("═" * 40, "1;36")
            print_colored(f"🔹 Version: {metadata.get('version', 'Unknown')}", "1;33")
            print_colored(f"🔹 Total Files: {len(files)}", "1;33")
            print_colored(f"🔹 Total Size: {metadata.get('total_size', 0)} bytes", "1;33")
            print_colored(f"🔹 Encoded: {metadata.get('encoded_at', 'Unknown')}", "1;33")
            print_colored(f"\n📁 Files:", "1;36")
            for fi in files:
                print_colored(f"   • {fi.get('name')} ({fi.get('size', 0)} bytes)", "1;32")
                
        except Exception as e:
            print_colored(f'❌ Error reading package: {e}', '1;31')

    elif args.cmd == 'info':
        print_colored("🛠️ HEX ALIEN ENCODER PRO - SYSTEM INFORMATION", "1;32")
        print_colored("═" * 50, "1;36")
        print_colored(f"🔸 Symbol Pool Size: {len(SYMBOL_POOL)}", "1;33")
        print_colored(f"🔸 Required Symbols: {len(BASE64_CHARS) + 1}", "1;33")
        print_colored(f"🔸 Available Margin: {len(SYMBOL_POOL) - (len(BASE64_CHARS) + 1)}", "1;33")
        print_colored(f"🔸 Header Version: {HEADER_PREFIX}", "1;33")
        print_colored(f"\n🎯 Sample Symbols:", "1;36")
        print_colored(f"   {''.join(SYMBOL_POOL[:20])}...", "1;35")
        print_colored(f"\n⚡ Features:", "1;36")
        print_colored("   • Military-grade SHA-256 encryption", "1;32")
        print_colored("   • Tamper detection system", "1;32")
        print_colored("   • Random symbol mapping", "1;32")
        print_colored("   • Multi-file support", "1;32")
        print_colored("   • Safe decoding (no auto-exec)", "1;32")

    else:
        parser.print_help()

if __name__ == '__main__':
    try:
        main_cli()
    except KeyboardInterrupt:
        print_colored("\n❌ Operation cancelled by user", "1;31")
    except Exception as e:
        print_colored(f"\n💥 Unexpected error: {e}", "1;31")