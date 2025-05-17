from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required
from datetime import datetime

pages_bp = Blueprint("pages", __name__)

@pages_bp.route("/attack_surface")
@login_required
def attack_surface():
    from app.models import AttackSurface
    attack_surfaces = AttackSurface.query.all()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template("attack_surface_content.html", attack_surfaces=attack_surfaces)
    return render_template("attack_surface.html", attack_surfaces=attack_surfaces)

@pages_bp.route("/findings")
@login_required
def findings():
    from app.models import Finding
    findings = Finding.query.all()
    return render_template("findings.html", findings=findings)

@pages_bp.route("/assets")
@login_required
def assets():
    from app.models import Asset
    assets = Asset.query.all()
    return render_template("assets.html", assets=assets)

@pages_bp.route("/reports")
@login_required
def reports():
    return render_template("reports.html")

@pages_bp.route("/new_scan")
@login_required
def new_scan():
    recent_tools = [
        {"title": "Port Scanner", "desc": "Scan open ports", "url": "/port-scanner", "icon": "port.png"},
        {"title": "Website Scanner", "desc": "Run ZAP scan", "url": "/zap_scan", "icon": "zap.png"},
        {"title": "Whois Lookup", "desc": "Domain ownership info", "url": "/whois-lookup", "icon": "whois.png"},
        {"title": "DNS Lookup", "desc": "Check DNS records", "url": "/dns-lookup", "icon": "dns.png"},
    ]
    return render_template("new_scan.html", recent_tools=recent_tools)

@pages_bp.route("/scan_progress")
@login_required
def scan_progress():
    return render_template("scan_progress.html")

@pages_bp.route("/scan_results")
@login_required
def scan_results():
    return render_template("scan_results.html")

@pages_bp.route("/website_scanner")
@login_required
def website_scanner():
    return render_template("website_scanner.html")

@pages_bp.route("/api/attack_surface_stats")
@login_required
def attack_surface_stats():
    from app.models import Asset, AttackSurface
    stats = {
        "domains": Asset.query.filter_by(asset_type='Domain').count(),
        "subdomains": Asset.query.filter_by(asset_type='Subdomain').count(),
        "ips": Asset.query.filter_by(asset_type='IP Address').count(),
        "endpoints": AttackSurface.query.count(),
        "technologies": Asset.query.filter(Asset.technologies != None, Asset.technologies != '').count(),
        "open_ports": Asset.query.filter(Asset.ports != None, Asset.ports != '').count(),
    }
    return jsonify(stats)

@pages_bp.route("/api/attack_surface_assets")
@login_required
def attack_surface_assets():
    from app.models import Asset, AttackSurface
    asset_type = request.args.get('type')
    # Treat 'Website' and 'Endpoint' as synonyms for endpoints
    if asset_type and asset_type.lower() in ['website', 'endpoint', 'endpoints']:
        endpoints = AttackSurface.query.all()
        assets_data = [
            {
                "id": e.id,
                "type": "Endpoint",
                "value": e.endpoint,
                "risk": "Low",  # Default or enhance if you have risk info
                "source": e.source or '',
                "first_seen": '',  # Not tracked in AttackSurface
                "last_seen": '',   # Not tracked in AttackSurface
                "tags": [],        # Not tracked in AttackSurface
            } for e in endpoints
        ]
        return jsonify(assets_data)
    elif asset_type:
        assets = Asset.query.filter_by(asset_type=asset_type).all()
    else:
        assets = Asset.query.all()
    assets_data = [
        {
            "id": a.id,
            "type": a.asset_type,
            "value": a.hostname or a.ip or '',
            "risk": a.risk,
            "source": a.source,
            "first_seen": a.last_seen.strftime('%Y-%m-%d') if a.last_seen else '',
            "last_seen": a.last_seen.strftime('%Y-%m-%d') if a.last_seen else '',
            "tags": a.tags.split(',') if a.tags else [],
        } for a in assets
    ]
    return jsonify(assets_data)