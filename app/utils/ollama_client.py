import requests

def ask_phi3(prompt: str, model="phi3") -> str:
    url = "http://localhost:11434/api/generate"

    response = requests.post(url, json={
        "model": model,
        "prompt": prompt,
        "stream": False
    })

    if response.ok:
        return response.json()["response"]
    else:
        raise Exception(f"Phi3 Ollama Error {response.status_code}: {response.text}")
