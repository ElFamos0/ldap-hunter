#!/usr/bin/env python3

import argparse
from pathlib import Path
from typing import Set, List
from rich import print
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text

console = Console()

def show_banner():
    banner = """
    ╔══════════════════════════════════════╗
    ║     LDAP Attribute Hunter v1.0       ║
    ║      [ The Silent Observer ]         ║
    ╚══════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))

def extract_ldap_attributes(file_path: str, progress: Progress) -> Set[str]:
    attributes = set()
    task = progress.add_task("[cyan]Analyzing LDAP dump...", total=None)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if ':' not in line or line.startswith('#'):
                    continue
                attr = line.split(':', 1)[0].strip()
                if attr:
                    attributes.add(attr)
        progress.update(task, completed=True)
        return attributes
    except Exception as e:
        progress.update(task, completed=True)
        console.print(f"[bold red]Error reading file: {e}[/]")
        return set()

def find_interesting_attributes(attributes: Set[str], progress: Progress) -> List[str]:
    task = progress.add_task("[cyan]Hunting for interesting attributes...", total=None)
    
    keywords = [
        'cascade', 'legacy', 'pwd', 'password', 'secret', 'cred',
        'hash', 'key', 'backup', 'admin', 'service', 'old', 'temp'
    ]
    
    interesting = []
    for attr in attributes:
        if any(keyword in attr.lower() for keyword in keywords):
            interesting.append(attr)
    
    progress.update(task, completed=True)
    return sorted(interesting)

def save_raw_output(file_path: str, attributes: Set[str], interesting: List[str]):
    with open(file_path, 'w', encoding='utf-8') as f:
        for attr in sorted(attributes):
            f.write(f"{attr}\n")

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='Advanced LDAP Attribute Analysis Tool')
    parser.add_argument('file', help='LDAP dump file to analyze')
    parser.add_argument('-o', '--output', help='Output file for raw attributes list')
    args = parser.parse_args()

    if not Path(args.file).exists():
        console.print(f"[bold red]File not found:[/] {args.file}")
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        attributes = extract_ldap_attributes(args.file, progress)
        interesting = find_interesting_attributes(attributes, progress)

    # Results display
    console.print("\n[bold green]Analysis Complete![/]\n")
    
    stats_panel = f"""
    Total Attributes Found: {len(attributes)}
    Interesting Attributes: {len(interesting)}
    Analyzed File: {args.file}
    """
    console.print(Panel(stats_panel, title="[bold cyan]Statistics", border_style="cyan"))

    if interesting:
        console.print("\n[bold yellow]Potentially Interesting Attributes:[/]")
        for attr in interesting:
            console.print(f"[bold red]►[/] [cyan]{attr}[/]")

    if args.output:
        save_raw_output(args.output, attributes, interesting)
        console.print(f"\n[green]Raw attributes list saved to:[/] {args.output}")

if __name__ == "__main__":
    main()