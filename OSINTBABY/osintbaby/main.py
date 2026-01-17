

import click
from rich.console import Console
from typing import Optional

from .core.utils import load_config, validate_input
from .modules import (
    DomainOSINT,
    IPOSINT,
    EmailOSINT,
    UsernameOSINT,
    PhoneOSINT,
    HashOSINT,
    ShodanOSINT,
)
from .output.formatter import OutputFormatter

console = Console()


@click.group()
@click.option('--config', '-c', default=None, help='Path to config file')
@click.option('--output', '-o', type=click.Choice(['table', 'json', 'csv']),
              default='table', help='Output format')
@click.option('--quiet', '-q', is_flag=True, help='Suppress banner')
@click.pass_context
def cli(ctx, config: Optional[str], output: str, quiet: bool):
    """OSINT CLI - Open Source Intelligence Command Line Tool
    
    A comprehensive tool for gathering intelligence from free OSINT services.
    """
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['formatter'] = OutputFormatter(output)
    
    if not quiet:
        OutputFormatter.print_banner()


@cli.command()
@click.argument('domain')
@click.pass_context
def domain(ctx, domain: str):
    """Perform domain reconnaissance.
    
    Gathers DNS records, WHOIS info, subdomains, technologies, and more.
    
    Example: osint domain example.com
    """
    if not validate_input("domain", domain):
        OutputFormatter.print_error(f"Invalid domain: {domain}")
        return
    
    module = DomainOSINT(ctx.obj['config'])
    results = module.run(domain)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('ip')
@click.pass_context
def ip(ctx, ip: str):
    """Perform IP address reconnaissance.
    
    Gathers geolocation, reverse DNS, ASN info, blacklist status, and more.
    
    Example: osint ip 8.8.8.8
    """
    if not validate_input("ip", ip):
        OutputFormatter.print_error(f"Invalid IP address: {ip}")
        return
    
    module = IPOSINT(ctx.obj['config'])
    results = module.run(ip)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('email')
@click.pass_context
def email(ctx, email: str):
    """Perform email reconnaissance.
    
    Checks breaches, validates email, finds associated accounts.
    
    Example: osint email user@example.com
    """
    if not validate_input("email", email):
        OutputFormatter.print_error(f"Invalid email: {email}")
        return
    
    module = EmailOSINT(ctx.obj['config'])
    results = module.run(email)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('username')
@click.pass_context
def username(ctx, username: str):
    """Search for username across social platforms.
    
    Similar to Sherlock - checks multiple platforms for username existence.
    
    Example: osint username johndoe
    """
    if not validate_input("username", username):
        OutputFormatter.print_error(f"Invalid username: {username}")
        return
    
    module = UsernameOSINT(ctx.obj['config'])
    results = module.run(username)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('phone')
@click.pass_context
def phone(ctx, phone: str):
    """Perform phone number reconnaissance.
    
    Identifies country, carrier, and validates the number.
    
    Example: osint phone +1234567890
    """
    if not validate_input("phone", phone):
        OutputFormatter.print_error(f"Invalid phone number: {phone}")
        return
    
    module = PhoneOSINT(ctx.obj['config'])
    results = module.run(phone)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('hash_value')
@click.pass_context
def hash(ctx, hash_value: str):
    """Lookup file hash in threat intelligence databases.
    
    Checks VirusTotal, MalwareBazaar, and other sources.
    
    Example: osint hash 44d88612fea8a8f36de82e1278abb02f
    """
    if not validate_input("hash", hash_value):
        OutputFormatter.print_error(f"Invalid hash: {hash_value}")
        return
    
    module = HashOSINT(ctx.obj['config'])
    results = module.run(hash_value)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('ip')
@click.pass_context
def shodan(ctx, ip: str):
    """Lookup IP in Shodan.
    
    Uses Shodan InternetDB (free) and Shodan API if configured.
    
    Example: osint shodan 8.8.8.8
    """
    if not validate_input("ip", ip):
        OutputFormatter.print_error(f"Invalid IP address: {ip}")
        return
    
    module = ShodanOSINT(ctx.obj['config'])
    results = module.run(ip)
    ctx.obj['formatter'].display(results, module.get_module_name())


@cli.command()
@click.argument('target')
@click.pass_context
def all(ctx, target: str):
    """Run all applicable modules on a target.
    
    Automatically detects target type and runs relevant modules.
    
    Example: osint all example.com
    """
    results = {}
    
    # Detect target type and run appropriate modules
    if validate_input("domain", target):
        OutputFormatter.print_info(f"Detected domain: {target}")
        module = DomainOSINT(ctx.obj['config'])
        results['domain'] = module.run(target)
        
    elif validate_input("ip", target):
        OutputFormatter.print_info(f"Detected IP: {target}")
        
        ip_module = IPOSINT(ctx.obj['config'])
        results['ip'] = ip_module.run(target)
        
        shodan_module = ShodanOSINT(ctx.obj['config'])
        results['shodan'] = shodan_module.run(target)
        
    elif validate_input("email", target):
        OutputFormatter.print_info(f"Detected email: {target}")
        module = EmailOSINT(ctx.obj['config'])
        results['email'] = module.run(target)
        
    elif validate_input("hash", target):
        OutputFormatter.print_info(f"Detected hash: {target}")
        module = HashOSINT(ctx.obj['config'])
        results['hash'] = module.run(target)
        
    else:
        # Assume username
        OutputFormatter.print_info(f"Treating as username: {target}")
        module = UsernameOSINT(ctx.obj['config'])
        results['username'] = module.run(target)
    
    for module_name, data in results.items():
        ctx.obj['formatter'].display(data, module_name.upper())


@cli.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"OSINT CLI version {__version__}")


@cli.command()
def list_modules():
    """List all available OSINT modules."""
    modules = [
        ("domain", "Domain reconnaissance (DNS, WHOIS, subdomains, technologies)"),
        ("ip", "IP address lookup (geolocation, ASN, blacklists)"),
        ("email", "Email investigation (breaches, validation, profiles)"),
        ("username", "Username enumeration across platforms"),
        ("phone", "Phone number lookup (country, carrier)"),
        ("hash", "File hash lookup (VirusTotal, MalwareBazaar)"),
        ("shodan", "Shodan IP lookup (ports, services, vulns)"),
    ]
    
    console.print("\n[bold cyan]Available OSINT Modules:[/bold cyan]\n")
    
    for name, description in modules:
        console.print(f"  [bold yellow]{name:12}[/bold yellow] - {description}")
    
    console.print()


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()