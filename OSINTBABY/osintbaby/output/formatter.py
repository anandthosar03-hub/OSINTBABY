"""Output formatting for OSINT results."""

import json
import csv
import io
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box


console = Console()


class OutputFormatter:
    """Format and display OSINT results."""

    def __init__(self, output_format: str = "table"):
        self.output_format = output_format

    def display(self, data: Dict[str, Any], module_name: str = ""):
        """Display data in the specified format."""
        if self.output_format == "json":
            self._display_json(data)
        elif self.output_format == "csv":
            self._display_csv(data)
        else:
            self._display_table(data, module_name)

    def _display_json(self, data: Dict[str, Any]):
        """Display data as JSON."""
        console.print_json(json.dumps(data, default=str, indent=2))

    def _display_csv(self, data: Dict[str, Any]):
        """Display data as CSV."""
        flat_data = self._flatten_dict(data)
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Key", "Value"])
        
        for key, value in flat_data.items():
            writer.writerow([key, value])
        
        console.print(output.getvalue())

    def _display_table(self, data: Dict[str, Any], module_name: str):
        """Display data as rich tables."""
        console.print()
        console.print(Panel(f"[bold cyan]{module_name} Results[/bold cyan]"))
        console.print()
        
        for key, value in data.items():
            if isinstance(value, dict):
                self._display_dict_as_table(key, value)
            elif isinstance(value, list):
                self._display_list(key, value)
            else:
                console.print(f"[bold]{key}:[/bold] {value}")
        
        console.print()

    def _display_dict_as_table(self, title: str, data: Dict[str, Any]):
        """Display a dictionary as a table."""
        table = Table(
            title=f"[bold yellow]{title}[/bold yellow]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        
        for key, value in data.items():
            if isinstance(value, (list, dict)):
                value = json.dumps(value, default=str)
            table.add_row(str(key), str(value))
        
        console.print(table)
        console.print()

    def _display_list(self, title: str, data: List[Any]):
        """Display a list of items."""
        if not data:
            console.print(f"[bold]{title}:[/bold] [dim]No data[/dim]")
            return
        
        if isinstance(data[0], dict):
            # Display as table
            table = Table(
                title=f"[bold yellow]{title}[/bold yellow]",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold magenta"
            )
            
            # Get all keys from first item
            keys = list(data[0].keys())
            for key in keys:
                table.add_column(str(key), style="cyan")
            
            for item in data:
                row = [str(item.get(k, "")) for k in keys]
                table.add_row(*row)
            
            console.print(table)
        else:
            # Display as tree
            tree = Tree(f"[bold yellow]{title}[/bold yellow]")
            for item in data:
                tree.add(str(item))
            console.print(tree)
        
        console.print()

    def _flatten_dict(
        self,
        d: Dict[str, Any],
        parent_key: str = "",
        sep: str = "."
    ) -> Dict[str, Any]:
        """Flatten a nested dictionary."""
        items = []
        
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v, default=str)))
            else:
                items.append((new_key, v))
        
        return dict(items)

    @staticmethod
    def print_banner():
        """Print the OSINT CLI banner."""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ███████╗██╗███╗   ██╗████████╗     ██████╗██╗      ║
║  ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝██║      ║
║  ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██║     ██║      ║
║  ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██║     ██║      ║
║  ╚██████╔╝███████║██║██║ ╚████║   ██║       ╚██████╗███████╗ ║
║   ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝        ╚═════╝╚══════╝ ║
║                                                               ║
║          Open Source Intelligence Command Line Tool           ║
║                        Version 1.0.0                          ║
╚═══════════════════════════════════════════════════════════════╝
        """
        console.print(banner, style="bold cyan")

    @staticmethod
    def print_success(message: str):
        """Print a success message."""
        console.print(f"[bold green]✓[/bold green] {message}")

    @staticmethod
    def print_error(message: str):
        """Print an error message."""
        console.print(f"[bold red]✗[/bold red] {message}")

    @staticmethod
    def print_warning(message: str):
        """Print a warning message."""
        console.print(f"[bold yellow]![/bold yellow] {message}")

    @staticmethod
    def print_info(message: str):
        """Print an info message."""
        console.print(f"[bold blue]ℹ[/bold blue] {message}")