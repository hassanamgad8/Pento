import requests, re, time, asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.utils.ollama_client import ask_phi3
from app.utils.report_writer import generate_html_report

visited_links = set()

def crawl_site_static(base_url, limit=20):
    to_visit = [base_url]
    all_links = set()

    while to_visit and len(all_links) < limit:
        url = to_visit.pop(0)
        if url in visited_links or not url.startswith(base_url):
            continue

        try:
            r = requests.get(url, timeout=10)
            visited_links.add(url)
            all_links.add(url)

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                full_url = urljoin(url, a["href"])
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    to_visit.append(full_url)

        except Exception as e:
            print(f"❌ Failed to crawl {url}: {e}")
            continue

    return list(all_links)

def extract_forms_bs4(html, page_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for i in form.find_all("input"):
            name = i.get("name") or i.get("id") or i.get("placeholder")
            if name:
                inputs.append(name)
        action = form.get("action") or page_url
        full_action = urljoin(page_url, action)
        method = form.get("method", "get").lower()
        forms.append({
            "form_html": str(form),
            "action": full_action,
            "method": method,
            "inputs": inputs
        })
    return forms

async def extract_forms_playwright(url):
    from playwright.async_api import async_playwright
    forms = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=30000)
            await page.wait_for_timeout(3000)

            # 🖼 Screenshot for debugging
            await page.screenshot(path="playwright_debug.png", full_page=True)
            print("🖼 Screenshot saved as playwright_debug.png")

            html = await page.content()
            soup = BeautifulSoup(html, "html.parser")
            form_elements = soup.find_all("form")

            if not form_elements:
                input_tags = soup.find_all("input")
                if input_tags:
                    fake_form = f"<form>{''.join(str(i) for i in input_tags)}</form>"
                    form_elements = [BeautifulSoup(fake_form, "html.parser").form]

            for form in form_elements:
                inputs = []
                for i in form.find_all("input"):
                    name = i.get("name") or i.get("id") or i.get("placeholder")
                    if name:
                        inputs.append(name)

                action = form.get("action") or url
                full_action = urljoin(url, action)
                method = form.get("method", "get").lower()
                forms.append({
                    "form_html": str(form),
                    "action": full_action,
                    "method": method,
                    "inputs": inputs
                })

        except Exception as e:
            print(f"❌ Playwright failed on {url}: {e}")
        finally:
            await browser.close()

    return forms

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

def test_payloads(form_info, payloads, type_, max_retries=1):
    results = []
    for payload in payloads:
        original = payload
        payload = clean_payload(payload)

        for field in form_info["inputs"]:
            data = {i: "" for i in form_info["inputs"]}
            data[field] = payload

            try:
                if form_info["method"] == "post":
                    r = requests.post(form_info["action"], data=data)
                else:
                    r = requests.get(form_info["action"], params=data)
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

                    if form_info["method"] == "post":
                        r2 = requests.post(form_info["action"], data=data)
                    else:
                        r2 = requests.get(form_info["action"], params=data)
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

def run_ai_site_scan(base_url):
    print(f"🌐 Crawling {base_url}")
    all_pages = crawl_site_static(base_url)
    print(f"🔎 Found {len(all_pages)} pages")

    results = []

    for page in all_pages:
        try:
            r = requests.get(page, timeout=10)
            forms = extract_forms_bs4(r.text, page)

            if not forms:
                print(f"🧠 No forms found via requests — using Playwright for {page}")
                forms = asyncio.run(extract_forms_playwright(page))

            for form in forms:
                prompt = f"""
                You are a professional pentester.

                Here is a form from {form['action']}:
                {form['form_html']}

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

                No explanations. Just raw payloads.
                """

                ai_output = ask_phi3(prompt)
                xss_payloads, sqli_payloads = extract_payloads_from_phi3(ai_output)

                form_result = {
                    "form_url": form["action"],
                    "method": form["method"],
                    "inputs": form["inputs"],
                    "ai_output": ai_output,
                    "tests": []
                }

                form_result["tests"].extend(test_payloads(form, xss_payloads, "XSS"))
                form_result["tests"].extend(test_payloads(form, sqli_payloads, "SQLi"))

                results.append(form_result)

        except Exception as e:
            print(f"❌ Failed to scan {page}: {e}")

    report = generate_html_report(results, base_url)
    print(f"✅ Report saved to: {report}")
    return results
