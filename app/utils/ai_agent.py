import requests, re, time
from bs4 import BeautifulSoup
from app.utils.ollama_client import ask_phi3
from app.utils.report_writer import generate_html_report

def extract_payloads_from_phi3(output_text):
    xss_list = re.findall(r"XSS:\s*((?:- .+\n?)+)", output_text, re.IGNORECASE)
    sqli_list = re.findall(r"SQLi:\s*((?:- .+\n?)+)", output_text, re.IGNORECASE)

    def parse_payloads(block):
        return [line.strip("- ").strip() for line in block.strip().splitlines() if line.strip().startswith("-")]

    xss_payloads = parse_payloads(xss_list[0]) if xss_list else []
    sqli_payloads = parse_payloads(sqli_list[0]) if sqli_list else []

    return xss_payloads, sqli_payloads

def analyze_response(text, payload):
    if payload.lower() in text.lower():
        return "🛑 Payload reflected"
    if "mysql" in text.lower() or "syntax error" in text.lower():
        return "🛑 SQL error found"
    return "✅ No issue detected"

def score_verdict(verdict):
    if "SQL error" in verdict:
        return 9
    elif "reflected" in verdict:
        return 7
    elif "Request failed" in verdict:
        return 3
    else:
        return 1

def clean_payload(p):
    p = p.replace("`", "").replace("'", "'").strip()
    p = p.split("#")[0]
    p = re.sub(r"//.*", "", p)
    return p.strip()

def test_payloads(form, payloads, type_, max_retries=1):
    results = []
    for payload in payloads:
        original = payload
        payload = clean_payload(payload)

        for field in form["inputs"]:
            data = {i: "" for i in form["inputs"]}
            data[field] = payload

            try:
                if form["method"] == "post":
                    r = requests.post(form["action"], data=data)
                else:
                    r = requests.get(form["action"], params=data)
                verdict = analyze_response(r.text, payload)
                score = score_verdict(verdict)

                results.append({
                    "type": type_,
                    "input": field,
                    "payload": payload,
                    "result": verdict,
                    "score": score,
                    "status_code": r.status_code
                })

                # Retry if weak
                if score < 5 and max_retries > 0:
                    retry_prompt = f"""
                    This {type_} payload had low impact or failed:

                    Payload: {original}

                    Improve it with 1 stronger version only.
                    Only give the new payload.
                    """
                    retry_output = ask_phi3(retry_prompt)
                    retry_payload = clean_payload(retry_output.strip().splitlines()[-1])
                    data[field] = retry_payload

                    if form["method"] == "post":
                        r2 = requests.post(form["action"], data=data)
                    else:
                        r2 = requests.get(form["action"], params=data)
                    verdict2 = analyze_response(r2.text, retry_payload)

                    results.append({
                        "type": type_,
                        "input": field,
                        "payload": retry_payload,
                        "result": verdict2,
                        "score": score_verdict(verdict2),
                        "status_code": r2.status_code
                    })

            except Exception as e:
                results.append({
                    "type": type_,
                    "input": field,
                    "payload": payload,
                    "result": f"❌ Request failed: {e}",
                    "score": 1,
                    "status_code": None
                })
    return results

def scan_form_static(url):
    html = requests.get(url).text
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    results = []

    for form in forms:
        inputs = [i.get("name") for i in form.find_all("input") if i.get("name")]
        action = form.get("action") or url
        full_action = requests.compat.urljoin(url, action)
        method = form.get("method", "get").lower()
        html_snippet = str(form)

        prompt = f"""
        You are a professional pentester.

        Form HTML:
        {html_snippet}

        Return exactly 10 different SQLi and 10 different XSS payloads.

        Format:
        SQLi:
        - payload1
        - payload2
        ...

        XSS:
        - payload1
        - payload2
        ...

        No explanation. Just raw payloads.
        """

        ai_output = ask_phi3(prompt)
        xss_payloads, sqli_payloads = extract_payloads_from_phi3(ai_output)

        scan_result = {
            "form_url": full_action,
            "method": method,
            "inputs": inputs,
            "ai_output": ai_output,
            "tests": []
        }

        scan_result["tests"].extend(test_payloads({
            "inputs": inputs,
            "method": method,
            "action": full_action
        }, xss_payloads, "XSS"))

        scan_result["tests"].extend(test_payloads({
            "inputs": inputs,
            "method": method,
            "action": full_action
        }, sqli_payloads, "SQLi"))

        results.append(scan_result)

    return results

def run_ai_test(url):
    print(f"🔎 Scanning {url}")
    results = scan_form_static(url)
    report = generate_html_report(results, url)
    print(f"✅ Report saved to: {report}")
    return results
