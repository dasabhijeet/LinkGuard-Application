import httpx

API_KEY = ''

response = httpx.post(
    "https://openrouter.ai/api/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    },
    json={
        "model": "openrouter/free",
        "messages": [
            {
                "role": "user",
                "content": "Say some memes"
            }
        ]
    },
    timeout=30,
)

print(response.status_code)
print(response.text)