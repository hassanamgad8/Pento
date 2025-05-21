from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from zapv2 import ZAPv2
import time
import os
import json
from app.utils.zap_report_writer import save_html_report, save_pdf_report_from_html
from datetime import datetime

# Create blueprint
zap_bp = Blueprint("zap", __name__)

# ZAP configuration
ZAP_API_KEY = "ot0dk3baml7b3ltlvauful3l75"
ZAP_ADDRESS = "127.0.0.1"
ZAP_PORT = 8090
ZAP_PROXY = f"http://{ZAP_ADDRESS}:{ZAP_PORT}"

# Initialize ZAP client
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

# Helper functions
def wait_zap(label, check_fn, id=None):
    """Wait for ZAP operation to complete and return progress percentage"""
    while True:
        status = check_fn(id) if id else check_fn()
        try:
            pct = int(status)
        except:
            pct = 0
        print(f"⏳ {label}: {pct}%")
        if pct >= 100:
            break
        time.sleep(2)
    return 100

# Routes
@zap_bp.route("/zap_scan", methods=["POST"])
@login_required
def zap_scan():
    """Start a ZAP scan with the provided options"""
    from app import db
    from app.models import Scan, RecentActivity
    try:
        data = request.get_json()
        url = data["url"]
        spider = data.get("spider", True)
        ajax = data.get("ajax", False)
        active = data.get("active", True)
        
        # Create Scan entry (status: running)
        scan = Scan(type='Website Scanner', status='running', started_at=datetime.utcnow(), user_id=current_user.id)
        db.session.add(scan)
        db.session.commit()
        
        # Access the target URL to initialize the site in ZAP
        zap.urlopen(url)
        time.sleep(2)
        
        # Create a unique scan ID (timestamp-based)
        timestamp = int(time.time())
        scan_id = f"{timestamp}-{url.replace('://', '-').replace('/', '-').replace(':', '-')}"
        
        # Store initial scan info in static folder
        scan_info = {
            "id": scan_id,
            "url": url,
            "timestamp": timestamp,
            "options": {
                "spider": spider,
                "ajax": ajax,
                "active": active
            },
            "status": "initialized",
            "progress": 0,
            "scan_db_id": scan.id
        }
        
        os.makedirs("app/static/scans", exist_ok=True)
        with open(f"app/static/scans/{scan_id}.json", "w") as f:
            json.dump(scan_info, f)
        
        return jsonify({
            "message": "✅ Scan initialized.",
            "scan_id": scan_id
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@zap_bp.route("/zap_scan_status", methods=["GET"])
@login_required
def zap_scan_status():
    """Check the status of a ZAP scan"""
    from app import db
    from app.models import Scan, RecentActivity, Asset, AttackSurface
    scan_id = request.args.get("scan_id")
    
    try:
        # Load current scan info
        with open(f"app/static/scans/{scan_id}.json", "r") as f:
            scan_info = json.load(f)
            
        # If scan is complete, just return current info
        if scan_info["status"] == "completed":
            return jsonify(scan_info)
            
        # If scan is running, check progress
        url = scan_info["url"]
        options = scan_info["options"]
        
        progress = 0
        current_stage = "Preparing"
        
        # Spider status
        if options["spider"]:
            if scan_info.get("spider_id"):
                spider_progress = int(zap.spider.status(scan_info["spider_id"]))
                if spider_progress < 100:
                    progress = spider_progress * 0.3  # Spider is 30% of total
                    current_stage = "Spider scanning"
                else:
                    progress = 30
            else:
                # Start spider if not started
                if scan_info["status"] == "initialized":
                    spider_id = zap.spider.scan(url)
                    scan_info["spider_id"] = spider_id
                    scan_info["status"] = "spider_running"
                    progress = 5
                    current_stage = "Spider scanning"
        else:
            progress = 30  # Skip spider phase
            
        # AJAX Spider status
        if options["ajax"] and progress >= 30:
            if scan_info.get("ajax_started"):
                # Check if still running
                if zap.ajaxSpider.status == "running":
                    progress = 30 + 10  # Assume 10% progress if running
                    current_stage = "AJAX Spider scanning"
                else:
                    progress = 45  # AJAX is 15% of total
            else:
                # Start AJAX Spider if not started
                if scan_info["status"] == "spider_completed" or not options["spider"]:
                    zap.ajaxSpider.scan(url)
                    scan_info["ajax_started"] = True
                    scan_info["status"] = "ajax_running"
                    progress = 35
                    current_stage = "AJAX Spider scanning"
        else:
            progress = 45  # Skip AJAX phase
            
        # Active scan status
        if options["active"] and progress >= 45:
            if scan_info.get("active_id"):
                active_progress = int(zap.ascan.status(scan_info["active_id"]))
                if active_progress < 100:
                    # Active scan is 45% of total
                    progress = 45 + (active_progress * 0.45)
                    current_stage = "Active scanning"
                else:
                    progress = 90
                    current_stage = "Finalizing"
                    
                    # If active scan is complete, generate reports
                    if scan_info["status"] != "generating_reports":
                        alerts = zap.core.alerts(baseurl=url)
                        
                        # Save reports
                        html_path = save_html_report(alerts, url)
                        pdf_path = save_pdf_report_from_html(html_path)
                        
                        # Save JSON alerts
                        json_filename = f"zap_alerts_{scan_id}.json"
                        json_path = os.path.join("app/static/reports", json_filename)
                        with open(json_path, "w") as f:
                            json.dump(alerts, f)
                        
                        # Add the scanned site as an Asset
                        asset = Asset(
                            hostname=url,
                            asset_type='Website',
                            source='Website Scanner',
                            last_seen=datetime.utcnow(),
                            risk='Med'
                        )
                        db.session.add(asset)
                        # Add endpoints as AttackSurface
                        endpoints = set()
                        for alert in alerts:
                            if 'url' in alert:
                                endpoints.add(alert['url'])
                        for ep in endpoints:
                            surface = AttackSurface(
                                scan_id=scan_info.get('scan_db_id'),
                                endpoint=ep,
                                param='',
                                source='Website Scanner'
                            )
                            db.session.add(surface)
                        # Update Scan entry to finished
                        scan = Scan.query.get(scan_info.get('scan_db_id'))
                        if scan:
                            scan.status = 'finished'
                            scan.finished_at = datetime.utcnow()
                        # Log RecentActivity
                        activity = RecentActivity(description=f"Website scan on {url} completed", user_id=scan.user_id if scan else None, scan_id=scan.id if scan else None)
                        db.session.add(activity)
                        db.session.commit()
                        
                        # Update scan info with report paths
                        scan_info["reports"] = {
                            "html": html_path.replace("app/static", "/static"),
                            "pdf": pdf_path.replace("app/static", "/static"),
                            "json": json_path.replace("app/static", "/static")
                        }
                        scan_info["alerts"] = alerts
                        scan_info["status"] = "generating_reports"
            else:
                # Start active scan if not started
                if scan_info["status"] == "ajax_completed" or (not options["ajax"] and (scan_info["status"] == "spider_completed" or not options["spider"])):
                    active_id = zap.ascan.scan(url)
                    scan_info["active_id"] = active_id
                    scan_info["status"] = "active_running"
                    progress = 50
                    current_stage = "Active scanning"
        else:
            if progress >= 45 and scan_info["status"] not in ["completed", "generating_reports"]:
                # We're done with all scans, generate reports
                alerts = zap.core.alerts(baseurl=url)
                
                # Save reports
                html_path = save_html_report(alerts, url)
                pdf_path = save_pdf_report_from_html(html_path)
                
                # Save JSON alerts
                json_filename = f"zap_alerts_{scan_id}.json"
                json_path = os.path.join("app/static/reports", json_filename)
                with open(json_path, "w") as f:
                    json.dump(alerts, f)
                
                # Add the scanned site as an Asset
                asset = Asset(
                    hostname=url,
                    asset_type='Website',
                    source='Website Scanner',
                    last_seen=datetime.utcnow(),
                    risk='Med'
                )
                db.session.add(asset)
                # Add endpoints as AttackSurface
                endpoints = set()
                for alert in alerts:
                    if 'url' in alert:
                        endpoints.add(alert['url'])
                for ep in endpoints:
                    surface = AttackSurface(
                        scan_id=scan_info.get('scan_db_id'),
                        endpoint=ep,
                        param='',
                        source='Website Scanner'
                    )
                    db.session.add(surface)
                # Update Scan entry to finished
                scan = Scan.query.get(scan_info.get('scan_db_id'))
                if scan:
                    scan.status = 'finished'
                    scan.finished_at = datetime.utcnow()
                # Log RecentActivity
                activity = RecentActivity(description=f"Website scan on {url} completed", user_id=scan.user_id if scan else None, scan_id=scan.id if scan else None)
                db.session.add(activity)
                db.session.commit()
                
                # Update scan info with report paths
                scan_info["reports"] = {
                    "html": html_path.replace("app/static", "/static"),
                    "pdf": pdf_path.replace("app/static", "/static"),
                    "json": json_path.replace("app/static", "/static")
                }
                scan_info["alerts"] = alerts
                scan_info["status"] = "generating_reports"
                progress = 95
                current_stage = "Finalizing"
                
        # Check for phase transitions
        if options["spider"] and scan_info["status"] == "spider_running" and int(zap.spider.status(scan_info["spider_id"])) >= 100:
            scan_info["status"] = "spider_completed"
            
        if options["ajax"] and scan_info["status"] == "ajax_running" and zap.ajaxSpider.status != "running":
            scan_info["status"] = "ajax_completed"
            
        if options["active"] and scan_info["status"] == "active_running" and int(zap.ascan.status(scan_info["active_id"])) >= 100:
            scan_info["status"] = "active_completed"
            
        # Check if we're completely done
        if (scan_info["status"] == "generating_reports" or 
            (not options["active"] and (scan_info["status"] == "ajax_completed" or (not options["ajax"] and scan_info["status"] == "spider_completed") or (not options["spider"] and scan_info["status"] == "initialized")))):
            scan_info["status"] = "completed"
            progress = 100
            current_stage = "Completed"
        
        # Update progress in scan info
        scan_info["progress"] = progress
        scan_info["current_stage"] = current_stage
        
        # Save updated scan info
        with open(f"app/static/scans/{scan_id}.json", "w") as f:
            json.dump(scan_info, f)
            
        return jsonify(scan_info)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@zap_bp.route("/zap_scan_results", methods=["GET"])
@login_required
def zap_scan_results():
    """Get the results of a completed ZAP scan"""
    scan_id = request.args.get("scan_id")
    
    try:
        # Load scan info
        with open(f"app/static/scans/{scan_id}.json", "r") as f:
            scan_info = json.load(f)
            
        if scan_info["status"] != "completed":
            return jsonify({"error": "Scan not completed yet"}), 400
            
        return jsonify(scan_info)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@zap_bp.route("/zap_scan_cancel", methods=["POST"])
@login_required
def zap_scan_cancel():
    """Cancel a running ZAP scan"""
    scan_id = request.json.get("scan_id")
    
    try:
        # Load scan info
        with open(f"app/static/scans/{scan_id}.json", "r") as f:
            scan_info = json.load(f)
        
        # Stop any running scans
        if scan_info.get("spider_id"):
            zap.spider.stop(scan_info["spider_id"])
            
        if scan_info.get("ajax_started"):
            zap.ajaxSpider.stop()
            
        if scan_info.get("active_id"):
            zap.ascan.stop(scan_info["active_id"])
        
        # Update scan info
        scan_info["status"] = "cancelled"
        scan_info["progress"] = 0
        
        # Save updated scan info
        with open(f"app/static/scans/{scan_id}.json", "w") as f:
            json.dump(scan_info, f)
            
        return jsonify({"message": "Scan cancelled successfully"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@zap_bp.route("/scan_partials/<partial>")
@login_required
def get_partial(partial):
    """Return partial templates for dynamic loading"""
    try:
        if partial == "progress":
            return render_template("_scan_progress.html")
        elif partial == "results":
            return render_template("_scan_results.html")
        else:
            return "Partial not found", 404
    except Exception as e:
        return str(e), 500