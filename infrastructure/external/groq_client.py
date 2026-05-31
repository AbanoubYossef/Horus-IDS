"""Groq LLM client for AI chatbot."""

import httpx


SYSTEM_PROMPT = """You are HORUS IDS AI Assistant, a cybersecurity expert embedded in a Network Intrusion Detection System (IDS) platform.

Your capabilities:
- Analyze network threats and attack patterns detected by the hierarchical ML model
- Explain attack types: DDoS, DoS (Hulk, GoldenEye, Slow), PortScan, Bot, Brute Force (FTP-Patator, SSH-Patator)
- Provide incident response recommendations
- Help SOC analysts understand severity levels and prioritize alerts
- Explain the hierarchical classification model (Level 1: 6 groups, Level 2: 11 fine-grained classes)
- Advise on network security best practices and mitigation strategies

The platform uses a Hierarchical XGBoost classifier trained on CIC-IDS2017, CIC-IDS2018, and CIC-DDoS2019 datasets achieving 98.70% weighted F1-score and 0.178% false alarm rate.

Attack severity mapping:
- Critical: DDoS, DDoS Amplification, DDoS Volumetric, DoS Hulk, DoS GoldenEye, DoS Slow
- High: Bot
- Medium: PortScan, FTP-Patator, SSH-Patator
- Info: BENIGN (normal traffic)

When given current platform statistics, use them to provide contextual, actionable analysis.
Always respond in a professional, concise manner suitable for SOC analysts.
If asked about something outside cybersecurity or IDS scope, politely redirect to your area of expertise."""


class GroqClient:
    def __init__(self, api_key: str, api_url: str, model: str):
        self._api_key = api_key
        self._api_url = api_url
        self._model = model

    async def chat(self, message: str, history: list[dict], platform_context: str = "") -> str:
        if not self._api_key:
            return (
                "AI module is not configured. Please set the GROQ_API_KEY environment variable "
                "with a valid Groq API key to enable the AI assistant.\n\n"
                "Get a free key at https://console.groq.com"
            )

        system_content = SYSTEM_PROMPT
        if platform_context:
            system_content += f"\n\nCurrent Platform Status:\n{platform_context}"

        messages = [{"role": "system", "content": system_content}]
        for h in history[-10:]:
            messages.append({"role": h.get("role", "user"), "content": h.get("content", "")})
        messages.append({"role": "user", "content": message})

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    self._api_url,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._model,
                        "messages": messages,
                        "temperature": 0.7,
                        "max_tokens": 1024,
                    },
                )
                if resp.status_code != 200:
                    detail = resp.json().get("error", {}).get("message", resp.text)
                    return f"AI service error: {detail}"
                return resp.json()["choices"][0]["message"]["content"]
        except httpx.TimeoutException:
            return "AI service timed out. Please try again."
        except Exception as e:
            return f"AI service error: {e}"
