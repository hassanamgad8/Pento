from zapv2 import ZAPv2
import time
import os
import json
from datetime import datetime
from app.utils.zap_report_writer import save_html_report, save_pdf_report_from_html

# ZAP configuration
ZAP_API_KEY = "ot0dk3baml7b3ltlvauful3l75"
ZAP_ADDRESS = "127.0.0.1"
ZAP_PORT = 8090
ZAP_PROXY = f"http://{ZAP_ADDRESS}:{ZAP_PORT}"

# Initialize ZAP client
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})

def wait_for_passive_scan():
    """Wait for passive scan to complete"""
    while int(zap.pscan.records_to_scan) > 0:
        print(f"Records to passive scan: {zap.pscan.records_to_scan}")
        time.sleep(2)

def run_zap_scan(target_url, use_spider=True, use_ajax=True, use_active=True):
    """
    Run a full ZAP scan and save the results
    
    Args:
        target_url: URL to scan
        use_spider: Whether to use traditional spider
        use_ajax: Whether to use AJAX spider
        use_active: Whether to run active scan
        
    Returns:
        Paths to the reports
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"Starting ZAP scan for {target_url} at {timestamp}")
    
    # Access the target
    zap.urlopen(target_url)
    time.sleep(2)
    
    # Traditional Spider
    if use_spider:
        print("Starting traditional spider...")
        spider_id = zap.spider.scan(target_url)
        
        # Wait for spider to complete
        while int(zap.spider.status(spider_id)) < 100:
            print(f"Spider progress: {zap.spider.status(spider_id)}%")
            time.sleep(2)
    
    # AJAX Spider
    if use_ajax:
        print("Starting AJAX spider...")
        zap.ajaxSpider.scan(target_url)
        
        # Wait for AJAX spider to complete
        while zap.ajaxSpider.status == "running":
            print("AJAX spider is running...")
            time.sleep(5)
            
    # Wait for passive scan to complete
    wait_for_passive_scan()
    
    # Active Scan
    if use_active:
        print("Starting active scan...")
        ascan_id = zap.ascan.scan(target_url)
        
        # Wait for active scan to complete
        while int(zap.ascan.status(ascan_id)) < 100:
            print(f"Active scan progress: {zap.ascan.status(ascan_id)}%")
            time.sleep(5)
    
    # Get alerts
    alerts = zap.core.alerts(baseurl=target_url)
    
    # Generate reports
    reports_dir = "app/static/reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    # Sanitize URL for filenames
    safe_url = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
    file_prefix = f"zap_scan_{safe_url}_{timestamp}"
    
    # Save HTML report
    html_path = save_html_report(alerts, target_url, output_dir=reports_dir)
    
    # Save PDF report
    pdf_path = save_pdf_report_from_html(html_path)
    
    # Save JSON report
    json_path = os.path.join(reports_dir, f"{file_prefix}.json")
    with open(json_path, "w") as f:
        json.dump(alerts, f)
    
    print(f"Scan completed. Reports saved to {reports_dir}")
    return html_path, pdf_path, json_path

def load_zap_results(target_url):
    """
    Load the most recent ZAP scan results for a target URL
    
    Args:
        target_url: URL that was scanned
        
    Returns:
        (alerts, html_path, pdf_path, json_path)
    """
    reports_dir = "app/static/reports"
    safe_url = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
    
    # Find all report files for this URL
    html_files = [f for f in os.listdir(reports_dir) if f.startswith(f"zap_scan_{safe_url}") and f.endswith(".html")]
    
    if not html_files:
        return [], "", "", ""
    
    # Get most recent report
    latest_html = sorted(html_files)[-1]
    html_path = os.path.join(reports_dir, latest_html)
    pdf_path = html_path.replace(".html", ".pdf")
    json_path = html_path.replace(".html", ".json")
    
    # Load alerts from JSON
    try:
        with open(json_path, "r") as f:
            alerts = json.load(f)
    except:
        alerts = []
    
    return alerts, html_path, pdf_path, json_path