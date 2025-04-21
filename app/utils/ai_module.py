import openai
import os

openai.api_key = os.getenv("OPENAI_API_KEY")

def run_ai_scan(target_url):
    prompt = f"""
You are a penetration testing assistant. Craft a SQL injection or XSS payload to exploit this URL:
{target_url}
Return only the payload and a short reason why it is likely to succeed.
"""
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
