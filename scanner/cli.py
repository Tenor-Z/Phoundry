import sys
import argparse
import asyncio
import json
import csv
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from .core import AsyncScannerEngine

console = Console()

def export_json(results, path):
    with open(path, "w") as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]✔[/bold green] Raw JSON intelligence exported to: [underline]{path}[/underline]")

def export_csv(results, path):
    if not results: return
    with open(path, "w", newline="") as f:
        # Get column headers from the first dictionary result keys
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    console.print(f"[bold green]✔[/bold green] Spreadsheet matrix layout exported to: [underline]{path}[/underline]")

def parse_arguments_and_run():
    parser = argparse.ArgumentParser(description="Phoundry - Safe, Non-Destructive PHP2Shell Audit Utility")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Single domain target")
    group.add_argument("-f", "--file", help="Newline-delimited file list input target path")
    
    parser.add_argument("--json", help="Export file output target path (JSON)")
    parser.add_argument("--csv", help="Export file output target path (CSV)")
    parser.add_argument("-c", "--concurrency", type=int, default=25)
    parser.add_argument("-o", "--timeout", type=int, default=5)

    args = parser.parse_args()
    targets = []

    if args.target:
        targets.append(args.target)
    elif args.file:
        try:
            with open(args.file, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[bold red]✗ Error:[/bold red] The file context '{args.file}' does not exist.")
            sys.exit(1)

    # Dynamic ASCII Art Frames for Phoundry
    BANNER_ART = """
 ██████╗ ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ ██████╗ ██╗   ██╗
 ██╔══██╗██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
 ██████╔╝███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║██████╔╝ ╚████╔╝ 
 ██╔═══╝ ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║██╔══██╗  ╚██╔╝  
 ██║     ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║   ██║   
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   
    """

    console.print("[yellow][*] Initializing Phoundry framework engines...[/yellow]")

    colors = ["cyan", "bold cyan", "bright_blue", "bold blue", "purple", "bold magenta"]
    
    with Live(console=console, refresh_per_second=8) as live:
        for i in range(12):
            current_color = colors[i % len(colors)]
            
            animated_panel = Panel(
                f"[{current_color}]{BANNER_ART}[/{current_color}]\n"
                f"[bold white]» Non-Destructive PHP2Shell Architecture Diagnostics «[/bold white]\n"
                f"[green]» Developed by Tenor-Z «[/green]\n\n"
                f"[dim]Engine Status: [/dim][green]Active[/green] | [dim]Cluster Load: [/dim][magenta]{len(targets)} Targets[/magenta]",
                border_style=current_color,
                title="[bold white] PHOUNDRY CORE FRAMEWORK [/bold white]",
                title_align="center"
            )
            
            live.update(animated_panel)
            time.sleep(0.12)

    engine = AsyncScannerEngine(targets=targets, concurrency=args.concurrency, timeout=args.timeout)
    results = asyncio.run(engine.run())

    table = Table(title="\nAudit Operational Results Summary", title_style="bold magenta", expand=True)
    table.add_column("Target URL Address", style="cyan", no_wrap=True)
    table.add_column("PHP Status", justify="center")
    table.add_column("Version", justify="center", style="bold")
    table.add_column("WAF/Proxy", justify="center", style="blue")
    table.add_column("Security Verdict", justify="center")
    table.add_column("Detailed Context / Remediations", style="dim")

    has_critical_findings = False

    for res in results:
        verdict = res["status"]
        if verdict in ["Vulnerable", "Legacy EOL"]:
            status_formatted = f"[bold blink red]{verdict}[/bold blink red]"
            has_critical_findings = True
        elif verdict == "Safe":
            status_formatted = f"[bold green]{verdict}[/bold green]"
        elif verdict in ["Review Required", "Unknown"]:
            status_formatted = f"[bold yellow]{verdict}[/bold yellow]"
        else:
            status_formatted = f"[white]{verdict}[/white]"

        php_indicator = "[green]Yes[/green]" if res["is_php"] else "[dim]No[/dim]"
        
        table.add_row(
            res["url"],
            php_indicator,
            res["version"],
            res["waf"],
            status_formatted,
            res["notes"]
        )

    console.print(table)
    console.print("\n")

    if args.json: export_json(results, args.json)
    if args.csv: export_csv(results, args.csv)

    if has_critical_findings:
        console.print("[bold red]⚠ Warning:[/bold red] At least one vulnerable target configuration was flagged.")
        sys.exit(2)
        
    sys.exit(0)
