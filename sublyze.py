#!/usr/bin/env python3

import argparse
import asyncio
import aiohttp
import socket
import re
import json
import random
import os
import sys
import dns.resolver
import dns.query
import dns.zone
from bs4 import BeautifulSoup
from itertools import product
from typing import List, Set
from termcolor import colored
from datetime import datetime
from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
    TaskProgressColumn,
)
from rich.table import Table
import logging
import time

console = Console()
logging.basicConfig(filename='sublyze.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

CONFIG_PATH = "config.json"

DEFAULT_CONFIG = {
    "shodan": "",
    "censys": {"id": "", "secret": ""},
    "virustotal": "",
    "securitytrails": "",
    "hunter": "",
    "urlscan": "",
    "binaryedge": "",
    "zoomeye": "",
    "netlas": "",
    "intelx": ""
}

if not os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)
        console.print("Generated default config.json")

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

def detect_takeover(subdomain: str) -> str:
    known_services = {
        "Amazon S3": "s3.amazonaws.com",
        "GitHub Pages": "github.io",
        "Heroku": "herokuapp.com",
        "Bitbucket": "bitbucket.io",
        "Cargo": "cargocollective.com",
        "Fastly": "fastly.net",
        "Shopify": "myshopify.com",
        "Squarespace": "squarespace.com",
        "Tumblr": "tumblr.com",
        "WordPress": "wordpress.com",
        "Wix": "wixsite.com",
        "Zendesk": "zendesk.com",
        "Readthedocs": "readthedocs.io",
        "Tilda": "tilda.ws",
        "Webflow": "webflow.io",
        "Helpjuice": "helpjuice.com",
        "Surge": "surge.sh",
        "Ghost": "ghost.io"
    }
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).lower()
            for service_name, indicator in known_services.items():
                if indicator in cname:
                    return service_name
    except:
        pass
    return None

def detect_waf(subdomain: str) -> str:
    try:
        ip = socket.gethostbyname(subdomain)
        if ip.startswith("104.") or ip.startswith("172."):
            return "Cloudflare"
    except:
        pass
    return "Unknown"

def recursive_enum(subdomain: str) -> List[str]:
    return [f"test.{subdomain}"]

async def passive_enum(domain: str) -> List[str]:
    subdomains = set()
    with console.status("[cyan]Querying crt.sh..."):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {"User-Agent": "Mozilla/5.0 (SubLyze)"}
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        try:
                            json_data = await response.json()
                            for entry in json_data:
                                name = entry.get("name_value", "")
                                for sub in name.split("\n"):
                                    if domain in sub:
                                        subdomains.add(sub.strip())
                        except Exception as parse_err:
                            console.print(f"[red]JSON parse error from crt.sh: {parse_err}")
                    else:
                        console.print(f"[red]crt.sh returned non-JSON. Status: {response.status}")
        except Exception as e:
            console.print(f"[red]Error during crt.sh query: {e}")
    return list(subdomains)

async def active_enum(domain: str, wordlist_path: str) -> List[str]:
    subdomains = set()
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Scanning:[/bold blue]"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("scan", total=len(words))
            for word in words:
                sub = f"{word}.{domain}"
                try:
                    socket.gethostbyname(sub)
                    subdomains.add(sub)
                except:
                    pass
                progress.advance(task)
    except Exception as e:
        console.print(f"[red]Error in active enumeration: {e}")
    return list(subdomains)

def takeover_check_from_file(file_path):
    if not os.path.exists(file_path):
        console.print(f"[red]Input file not found: {file_path}")
        return

    with open(file_path, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    console.print("\n[bold]🔐 Subdomain Takeover Check:[/bold]\n")
    for domain in domains:
        service = detect_takeover(domain)
        if service:
            console.print(f"[yellow][Takeover Risk][/yellow] {domain} ➜ {service}")
        else:
            console.print(f"[green][Safe][/green] {domain}")

async def check_live_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]❌ File not found: {file_path}[/bold red]")
        return

    console.print(f"\n[cyan]📡 Checking live subdomains (HTTP/HTTPS) from [bold]{file_path}[/bold][/cyan]\n")
    results = []
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for sub in subdomains:
            live = False
            for protocol in ["http", "https"]:
                url = f"{protocol}://{sub}"
                try:
                    async with session.get(url, allow_redirects=True) as response:
                        if response.status < 400:
                            console.print(f"[bold green][Live][/bold green] {url} ✅")
                            results.append(url)
                            live = True
                            break
                except:
                    continue
            if not live:
                console.print(f"[bold red][Dead][/bold red] {sub} ❌")

    if results:
        with open("live_subdomains.txt", "w") as out:
            for live_url in results:
                out.write(f"{live_url}\n")
        console.print(f"\n[bold green]📄 Saved live subdomains to live_subdomains.txt[/bold green]\n")

async def main():
    parser = argparse.ArgumentParser(description="SubLyze - Advanced Subdomain Recon Engine")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for brute-forcing")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--passive", action="store_true", help="Enable passive enumeration")
    parser.add_argument("--active", action="store_true", help="Enable active enumeration")
    parser.add_argument("--all", action="store_true", help="Run passive and active enumeration")
    parser.add_argument("-live", metavar="FILE", help="Check live subdomains from a file")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds for network requests (default: 10)")
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between requests (default: 0)")
    parser.add_argument("--silent", action="store_true", help="Run in silent mode without banners")
    parser.add_argument("--dns-resolver", help="Custom DNS resolver (e.g., 8.8.8.8)")
    parser.add_argument("--takeover", help="Check for potential subdomain takeovers (single domain or file path)")
    parser.add_argument("--recursive", action="store_true", help="Perform recursive subdomain enumeration")
    parser.add_argument("--waf-check", action="store_true", help="Detect WAF/CDN protection on subdomains")
    parser.add_argument("--mode", choices=["light", "aggressive"], help="Scan mode presets")

    args = parser.parse_args()

    if args.mode:
        if args.mode == "light":
            args.threads = 50
            args.timeout = 5
            args.delay = 0.1
        elif args.mode == "aggressive":
            args.threads = 200
            args.timeout = 15
            args.delay = 0

    if not args.silent:
        banner = (
            "[bold cyan]╔══════════════════════════════════╗[/bold cyan]\n"
            "[bold cyan]║[/bold cyan]    [bold yellow]╭─[ SubLyze ]───────╮[/bold yellow]         [bold cyan]║[/bold cyan]\n"
            "[bold cyan]║[/bold cyan]    │  Subdomain Intel  │  [bold magenta]v1.1[/bold magenta]   [bold cyan]║[/bold cyan]\n"
            "[bold cyan]║[/bold cyan]    │  by [bold green]R3XD[/bold green]           ╰────────╯[bold cyan]\n"
            "[bold cyan]╚══════════════════════════════════╝[/bold cyan]\n"
            "\n[bold]Legend:[/bold]\n"
            "[cyan][Passive][/cyan]  [green][Active][/green]  [yellow][Takeover Risk][/yellow]  [magenta][Recursive][/magenta]  [blue][WAF][/blue]\n"
        )
        console.print(banner)

    if args.live:
        await check_live_from_file(args.live)
        return

    if args.takeover:
        if os.path.isfile(args.takeover):
            takeover_check_from_file(args.takeover)
            return

    if not args.domain:
        console.print("[red]Error: Please specify a domain using -d or use -live or --takeover with file.")
        return

    if args.all:
        args.passive = True
        args.active = True

    all_subdomains = set()

    if args.passive:
        subs = await passive_enum(args.domain)
        all_subdomains.update(subs)
        for sub in subs:
            console.print(f"{sub}")

    if args.active and args.wordlist:
        subs = await active_enum(args.domain, args.wordlist)
        all_subdomains.update(subs)
        for sub in subs:
            console.print(f"{sub}")

    if args.takeover and not os.path.isfile(args.takeover):
        for sub in all_subdomains:
            service = detect_takeover(sub)
            if service:
                console.print(f"[yellow][Takeover Risk][/yellow] {sub} ➜ {service}")

    if args.recursive:
        for sub in all_subdomains:
            recursed = recursive_enum(sub)
            for r in recursed:
                console.print(f"[magenta][Recursive][/magenta] {r}")

    if args.waf_check:
        for sub in all_subdomains:
            waf = detect_waf(sub)
            console.print(f"[blue][WAF][/blue] {sub} ➜ {waf}")

    if args.output:
        with open(args.output, 'w') as f:
            for sub in sorted(all_subdomains):
                f.write(sub + '\n')
        console.print(f"\n[green]Saved results to {args.output}[/green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
