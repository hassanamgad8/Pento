from flask import Blueprint, request, jsonify
from app.utils.ai_agent import run_ai_test       # single-page scan
from app.utils.ai_crawler import run_ai_site_scan  # full-site scan

ai_scan_bp = Blueprint("ai_scan", __name__)

@ai_scan_bp.route("/ai_test", methods=["POST"])
def run_ai_test_endpoint():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    results = run_ai_test(url)
    return jsonify(results)

@ai_scan_bp.route("/site_scan", methods=["POST"])
def site_scan():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        results = run_ai_site_scan(url)
        return jsonify({"message": "✅ Scan complete", "total_forms": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
