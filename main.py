# main.py
# SOC Analyst Agentic AI - Proof-of-Concept Step 2
# This script integrates with an Ollama LLM (Llama 2) to dynamically
# generate an investigation plan, replacing the previous hardcoded approach.

import os
import json
import time
import requests
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")

# --- Pydantic Models for Data Validation ---
# (These models remain the same as in Step 1)
class EntityModel(BaseModel):
    """Represents an entity involved in an alert (e.g., user, host, IP)."""
    user: str | None = None
    hostname: str | None = None
    process_name: str | None = None
    process_id: str | None = None
    ip_address_src: str | None = None
    command_line: str | None = None

class NormalizedAlert(BaseModel):
    """Standardized alert schema. All incoming data is converted to this format."""
    alert_id: str
    source_tool: str
    timestamp_utc: str
    title: str
    severity_source: str
    entities: EntityModel
    raw_data: Dict[str, Any]


# --- 1. Perception Module (Component) ---
app = FastAPI(
    title="SOC Analyst Agentic AI - PoC (LLM Integrated)",
    description="Receives security alerts and uses Ollama to generate and execute an investigation plan.",
    version="0.2.0"
)

# --- 4. Toolbelt / Skills Module (Mock Implementation) ---
# Each function's docstring is critical, as it's passed to the LLM
# so it knows what tools are available and how to use them.

def lookup_ip_threat_intel(ip_address: str) -> dict:
    """
    Looks up an IP address in a mock threat intelligence database to check if it's malicious.
    
    :param ip_address: The IP address to look up.
    :return: A dictionary with threat intelligence information.
    """
    print(f"--- [Tool Executed]: Looking up IP: {ip_address} ---")
    time.sleep(1)
    known_malicious_ips = {
        "8.8.8.8": {"is_malicious": False, "provider": "Google DNS"},
        "1.2.3.4": {"is_malicious": True, "threat_type": "C2 Server", "confidence": "High"},
        "203.0.113.55": {"is_malicious": False, "notes": "Benign corporate VPN endpoint."}
    }
    return known_malicious_ips.get(ip_address, {"is_malicious": False, "notes": "No intelligence found."})

def get_user_details(username: str) -> dict:
    """
    Retrieves details for a user (like role and manager) from a mock identity provider.

    :param username: The username to retrieve details for.
    :return: A dictionary with user details.
    """
    print(f"--- [Tool Executed]: Getting details for user: {username} ---")
    time.sleep(1)
    user_database = {
        "j.doe": {"full_name": "John Doe", "role": "Software Engineer", "manager": "A. Smith"},
        "a.smith": {"full_name": "Alice Smith", "role": "Engineering Manager", "manager": "C. Brown"}
    }
    return user_database.get(username, {"error": "User not found."})

TOOL_REGISTRY = {
    "threat_intel.lookup_ip": lookup_ip_threat_intel,
    "identity.get_user_details": get_user_details,
}

# --- 2. Cognitive Core (Planner - NEW) ---
# This is the new component that interacts with the LLM.

def get_tools_description() -> str:
    """Formats the tool registry into a string for the LLM prompt."""
    descriptions = []
    for name, func in TOOL_REGISTRY.items():
        descriptions.append(f"- Tool Name: `{name}`\n  Description: {func.__doc__.strip()}")
    return "\n".join(descriptions)

SYSTEM_PROMPT = f"""
You are an expert SOC Analyst AI. Your task is to create a step-by-step investigation plan for a given security alert.
You will be given the alert data and a list of available tools you can use.
For each step in your plan, you must provide the tool name, the parameters for the tool, and your reasoning for why that step is necessary.

Available Tools:
{get_tools_description()}

You MUST respond with ONLY a valid JSON object. Do not include any other text, greetings, or explanations.
The JSON object must follow this exact schema:
{{
  "plan": [
    {{
      "tool_name": "...",
      "params": {{...}},
      "reasoning": "..."
    }}
  ]
}}
"""

def generate_plan_with_ollama(alert: NormalizedAlert) -> Dict[str, Any]:
    """
    Generates an investigation plan using an Ollama LLM.
    This is the core of the "Decide" step in the OODA loop.
    """
    print("--- [Cognitive Core]: Contacting LLM to generate investigation plan... ---")
    
    user_prompt = f"Create an investigation plan for the following alert:\n\n{alert.model_dump_json(indent=2)}"

    payload = {
        "model": "llama2",
        "prompt": user_prompt,
        "system": SYSTEM_PROMPT,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9
        }
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=60)
        response.raise_for_status()
        
        # The response from Ollama is a string, so we need to parse it into JSON.
        response_json = json.loads(response.text)
        plan_json_str = response_json.get("response", "{}")
        
        # A second parse is needed because the 'response' field is a JSON string.
        plan = json.loads(plan_json_str)
        
        print("--- [Cognitive Core]: LLM generated the following plan: ---")
        print(json.dumps(plan, indent=2))
        
        return plan
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not connect to Ollama API at {OLLAMA_API_URL}. {e}")
        return {"error": "Failed to connect to LLM."}
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON response from LLM. Response: {plan_json_str}. Error: {e}")
        return {"error": "Invalid JSON response from LLM."}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"error": "An unexpected error occurred during plan generation."}


# --- 2 & 5. Cognitive Core & Action Module (Orchestrator - UPDATED) ---

def run_investigation(alert: NormalizedAlert):
    """Orchestrates the alert investigation process by generating and executing a dynamic plan."""
    print("\n" + "="*50)
    print(f"🕵️  Starting Investigation for Alert ID: {alert.alert_id}")
    print("="*50 + "\n")

    # The 'Decide' step is now dynamic.
    plan_data = generate_plan_with_ollama(alert)

    if "error" in plan_data or not plan_data.get("plan"):
        print("❌ Investigation failed: Could not generate a valid plan.")
        return

    investigation_plan = plan_data["plan"]
    
    # The 'Act' step: Execute the dynamically generated plan.
    investigation_results = []
    for step in investigation_plan:
        tool_name = step.get("tool_name")
        params = step.get("params", {})
        
        if tool_name in TOOL_REGISTRY:
            tool_function = TOOL_REGISTRY[tool_name]
            try:
                result = tool_function(**params)
                investigation_results.append({
                    "step_reasoning": step.get("reasoning", "No reasoning provided."),
                    "tool_used": tool_name,
                    "findings": result
                })
            except Exception as e:
                investigation_results.append({"step_reasoning": step.get("reasoning"), "error": str(e)})
        else:
            investigation_results.append({"step_reasoning": step.get("reasoning"), "error": f"Tool '{tool_name}' not found."})

    # Final Summary (part of the 'Act' / Output module)
    print("\n" + "="*50)
    print("✅ Investigation Complete. Summary:")
    print("="*50)
    print(f"Alert Title: {alert.title}")
    print("\n--- Findings ---")
    print(json.dumps(investigation_results, indent=2))
    print("\n" + "="*50 + "\n")


@app.post("/webhook/alert")
async def handle_alert_webhook(alert: NormalizedAlert, background_tasks: BackgroundTasks):
    """Webhook endpoint to receive normalized security alerts."""
    print(f"Received alert {alert.alert_id}. Queuing for investigation.")
    background_tasks.add_task(run_investigation, alert)
    return {"status": "success", "message": "Alert received and queued for investigation."}

# To run this PoC:
# 1. Ensure you have Ollama running with the 'llama2' model installed (`ollama pull llama2`).
# 2. Install necessary libraries: `pip install fastapi uvicorn python-dotenv requests`
# 3. Create a file named `.env` in the same directory with this content:
#    OLLAMA_API_URL=http://localhost:11434/api/generate
# 4. Run the server: `uvicorn main:app --reload`
# 5. Send a POST request to http://127.0.0.1:8000/webhook/alert using the same curl command as before.
