import os
from openai import OpenAI

client = OpenAI(
    api_key="AIzaSyBFH603cB19vzv2LMYvha970DDTm4ujem4",
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
)

try:
    response = client.chat.completions.create(
        model="gemini-1.5-flash",
        messages=[{"role": "user", "content": "Hello"}]
    )
    print("gemini-1.5-flash success!")
    print(response.choices[0].message.content)
except Exception as e:
    print(f"gemini-1.5-flash error: {e}")

try:
    response = client.chat.completions.create(
        model="gemini-1.5-pro",
        messages=[{"role": "user", "content": "Hello"}]
    )
    print("gemini-1.5-pro success!")
    print(response.choices[0].message.content)
except Exception as e:
    print(f"gemini-1.5-pro error: {e}")
