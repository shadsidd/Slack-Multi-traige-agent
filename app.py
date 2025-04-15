import os
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.models.google import Gemini
from pydantic import BaseModel
import re
import streamlit as st
import pandas as pd
import json
import time

# Load environment variables from .env file as defaults
load_dotenv()

# Persistent storage files
HISTORY_FILE = "alert_history.json"
SETTINGS_FILE = "settings.json"

# Structured output models
class Classification(BaseModel):
    classification: str
    confidence: int

class Triage(BaseModel):
    triage_status: str

class Correlation(BaseModel):
    correlation: str

class Remediation(BaseModel):
    remediation: str

# Persistence functions
def save_data(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f)

def load_data(file_path, default):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    return default

# Initialize session state
if 'alert_history' not in st.session_state:
    st.session_state['alert_history'] = load_data(HISTORY_FILE, [])
if 'settings' not in st.session_state:
    st.session_state['settings'] = load_data(SETTINGS_FILE, {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
        "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""),
        "SLACK_TOKEN": os.getenv("SLACK_TOKEN", ""),
        "SOURCE_CHANNEL_ID": "C07Mxxxxx",
        "ALERT_CHANNEL_ID": "C07Nxxxxx",
        "SEVERITY_THRESHOLD": 80  # New: default severity threshold
    })
if 'log' not in st.session_state:
    st.session_state['log'] = []
if 'cron_running' not in st.session_state:
    st.session_state['cron_running'] = False
if 'agent_instructions' not in st.session_state:
    st.session_state['agent_instructions'] = {
        "classifier": """
        As a security engineer Analyze the alert content and metadata from the provided JSON input. Classify it as 'Real Threat', 'False Positive', or 'Low Priority'.
        Provide a confidence score (0-100) based on your reasoning.
        Examples:
        - '{"content": "An unprotected port is being probed by a known malicious host", "severity": 2}' -> Real Threat, high confidence.
        - '{"content": "User removed from repository", "severity": "LOW"}' -> Low Priority, medium confidence.
        - '{"content": "Routine DNS update", "reason": "Routine DNS Record Update"}' -> False Positive, high confidence.
        """,
        "triage": """
        Based on the alert JSON, its classification, and confidence, assign a triage status:
        - 'Real Threat' with confidence >= 80: 'Suspicious'
        - 'Low Priority' or 'False Positive': 'Resolved'
        - Otherwise: 'Fix in Progress'
        """,
        "correlation": """
        Given the current alert JSON and a list of past alerts in 'history', identify patterns (e.g., same account, region, type).
        Return a string describing correlations or 'No correlations found'.
        """,
        "remediation": """
        Suggest remediation steps based on the alert JSON, classification, triage status, and correlations.
        Examples:
        - Real Threat (port probing): 'Close the port and block the IP.'
        - Low Priority (user removal): 'No action required.'
        - False Positive (DNS update): 'Log and ignore.'
        """
    }

# Slack client
slack_client = WebClient(token=st.session_state['settings']['SLACK_TOKEN'])

# Agent initialization
def initialize_agent(instructions: str, api_keys: dict) -> Agent:
    # Create a placeholder agent without requiring API keys
    # This allows the app to load without errors
    model = OpenAIChat(id="gpt-4o")
    return Agent(model=model, instructions=instructions)

# Function to check if API keys are available when needed
def check_api_keys(api_keys: dict) -> bool:
    openai_key = api_keys.get("OPENAI_API_KEY")
    gemini_key = api_keys.get("GOOGLE_API_KEY")
    
    if not openai_key and not gemini_key:
        st.warning("No LLM API key provided. Please set your API keys in the Settings tab.")
        return False
    return True

# Initialize agents with dynamic instructions
classifier_agent = initialize_agent(st.session_state['agent_instructions']['classifier'], st.session_state['settings'])
triage_agent = initialize_agent(st.session_state['agent_instructions']['triage'], st.session_state['settings'])
correlation_agent = initialize_agent(st.session_state['agent_instructions']['correlation'], st.session_state['settings'])
remediation_agent = initialize_agent(st.session_state['agent_instructions']['remediation'], st.session_state['settings'])

# Helper function to update agents
def update_agents(instructions, settings):
    global classifier_agent, triage_agent, correlation_agent, remediation_agent
    classifier_agent = initialize_agent(instructions["classifier"], settings)
    triage_agent = initialize_agent(instructions["triage"], settings)
    correlation_agent = initialize_agent(instructions["correlation"], settings)
    remediation_agent = initialize_agent(instructions["remediation"], settings)

# Core functions
def fetch_slack_alerts(channel_id: str) -> list:
    try:
        response = slack_client.conversations_history(channel=channel_id, limit=10)
        alerts = [msg for msg in response["messages"] if "content" in msg or isinstance(msg.get("text"), str)]
        return [{"content": msg.get("text", ""), **msg.get("metadata", {})} for msg in alerts]
    except SlackApiError as e:
        st.session_state['log'].append(f"Error fetching Slack messages: {e}")
        return []

def post_to_alert_channel(channel_id: str, message: str):
    try:
        slack_client.chat_postMessage(channel=channel_id, text=message)
        st.session_state['log'].append(f"Posted to alert channel: {message}")
    except SlackApiError as e:
        st.session_state['log'].append(f"Error posting to alert channel: {e}")

def process_alert(alert: dict) -> dict:
    # Check if API keys are available
    if not check_api_keys(st.session_state['settings']):
        return {
            "classification": "Error",
            "confidence": 0,
            "triage_status": "Error",
            "correlation": "API keys required",
            "remediation": "Please set your API keys in the Settings tab",
            "severity": "Low",
            "timestamp": time.ctime()
        }
    
    alert_message = {"role": "user", "content": str(alert)}
    
    # Step 1: Classify
    classification_output = classifier_agent.run(alert_message, response_format=Classification)
    classification_text = classification_output.content
    try:
        if "Real Threat" in classification_text:
            classification = "Real Threat"
        elif "False Positive" in classification_text:
            classification = "False Positive"
        elif "Low Priority" in classification_text:
            classification = "Low Priority"
        else:
            classification = "Unknown"
        
        confidence = 0
        for pattern in [r'confidence (\d+)', r'confidence: (\d+)', r'(\d+)%', r'(\d+) percent']:
            match = re.search(pattern, classification_text, re.IGNORECASE)
            if match:
                confidence = int(match.group(1))
                break
        if confidence == 0:
            if "high confidence" in classification_text.lower():
                confidence = 85
            elif "medium confidence" in classification_text.lower():
                confidence = 65
            elif "low confidence" in classification_text.lower():
                confidence = 40
    except Exception as e:
        st.session_state['log'].append(f"Error parsing classification: {e}")
        classification = "Error"
        confidence = 0
    
    # Step 2: Triage
    triage_input = {"role": "user", "content": str({"alert": alert, "classification": classification, "confidence": confidence})}
    triage_output = triage_agent.run(triage_input, response_format=Triage)
    triage_text = triage_output.content
    try:
        if "Suspicious" in triage_text:
            triage_status = "Suspicious"
        elif "Resolved" in triage_text:
            triage_status = "Resolved"
        elif "Fix in Progress" in triage_text:
            triage_status = "Fix in Progress"
        else:
            triage_status = triage_text.strip().split('\n')[0]
    except:
        triage_status = "Fix in Progress"
    
    # Step 3: Correlate
    correlation_input = {"role": "user", "content": str({"alert": alert, "history": st.session_state['alert_history']})}
    correlation_output = correlation_agent.run(correlation_input, response_format=Correlation)
    correlation_text = correlation_output.content
    try:
        if "No correlations found" in correlation_text or "No correlation" in correlation_text:
            correlation_info = "No correlations found"
        else:
            correlation_info = correlation_text.strip().split('\n\n')[0]
    except:
        correlation_info = "No correlations found"
    
    # Step 4: Remediate
    remediation_input = {"role": "user", "content": str({"alert": alert, "classification": classification, "confidence": confidence, "triage_status": triage_status, "correlation": correlation_info})}
    remediation_output = remediation_agent.run(remediation_input, response_format=Remediation)
    remediation_text = remediation_output.content
    try:
        remediation_steps = remediation_text.strip().split('\n\n')[0]
    except:
        remediation_steps = "No specific remediation recommended"
    
    # Severity Scoring (New Feature, with fallback for old entries)
    threshold = st.session_state['settings'].get('SEVERITY_THRESHOLD', 80)
    severity = "Low"
    if classification == "Real Threat" and confidence >= threshold:
        severity = "High"
    elif classification == "Real Threat" or confidence >= 50:
        severity = "Medium"
    
    result = {
        "classification": classification,
        "confidence": confidence,
        "triage_status": triage_status,
        "correlation": correlation_info,
        "remediation": remediation_steps,
        "severity": severity,
        "timestamp": time.ctime()  # For Dashboard and filtering
    }
    
    st.session_state['alert_history'].append({"alert": alert, "analysis": result})
    save_data(HISTORY_FILE, st.session_state['alert_history'])
    st.session_state['log'].append(f"Processed alerts: {alert['content']} -> {result}")
    return result

def process_sample_alerts():
    sample_alerts = [
        {"content": "An unprotected port on EC2 instance i-02cd504323687f8e is being probed by a known malicious host.", "severity": 2, "region": "ap-south-1", "account": "js_tilemedia"},
        {"content": "User User369 has been removed from the repository (org.remove_member action).", "severity": "LOW", "repository_path": "$repo"},
        {"content": "Subdomain origin-live1 DNS record modified (CNAME). Metadata shows Route53 source as company_aws_prod.", "subdomain": "origin-live1", "reason": "Routine DNS Record Update"}
    ]
    processed_count = 0
    real_threat_count = 0
    results = []
    for alert in sample_alerts:
        processed_count += 1
        result = process_alert(alert)
        results.append({"alert": alert, "analysis": result, "source": "Sample"})
        if result["classification"] == "Real Threat":
            real_threat_count += 1
    st.session_state['log'].append(f"Processed {processed_count} sample alerts. Real threats: {real_threat_count}")
    return results

def run_scheduled_task(channel_id):
    alerts = fetch_slack_alerts(channel_id)
    if not alerts:
        st.session_state['log'].append("No new alerts found.")
        return []
    processed_count = 0
    real_threat_count = 0
    results = []
    for i, alert in enumerate(alerts):
        processed_count += 1
        result = process_alert(alert)
        results.append({"alert": alert, "analysis": result, "source": "Slack"})
        if result["classification"] == "Real Threat":
            real_threat_count += 1
        if st.session_state.get('cron_running', False):  # Progress for cron
            st.session_state['cron_progress'] = f"Processed {i + 1}/{len(alerts)} alerts"
    summary_message = f"Summary: Processed {processed_count} alerts. Real threats: {real_threat_count}"
    post_to_alert_channel(st.session_state['settings']['ALERT_CHANNEL_ID'], summary_message)
    st.session_state['log'].append(summary_message)
    return results

# Streamlit UI
def main():
    st.set_page_config(page_title="Slack Auto Triage", layout="wide")
    st.title("Slack Auto Triage Agent")
    
    # Sidebar for Run Agents input
    with st.sidebar:
        st.header("Run Agents Input")
        sample_alerts = [
            {"content": "An unprotected port on EC2 instance i-02cd5073838687f8e is being probed by a known malicious host.", "severity": 2},
            {"content": "User santoshkadam369 has been removed from the repository.", "severity": "LOW"},
            {"content": "Routine DNS update detected.", "reason": "Routine DNS Record Update"},
            {"content": "Suspicious login attempt from IP 192.168.1.1.", "severity": 3},
            {"content": "File permissions changed unexpectedly.", "severity": 1}
        ]
        selected_sample = st.selectbox("Select Sample Alert", options=[json.dumps(a) for a in sample_alerts], format_func=lambda x: json.loads(x)["content"], key="sample_select")
        custom_alert = st.text_area("Or Enter Custom Alert JSON", value=selected_sample, key="custom_alert")
        if st.button("Validate JSON", key="validate_button"):
            try:
                json.loads(custom_alert)
                st.success("Valid JSON")
            except json.JSONDecodeError:
                st.error("Invalid JSON format")
        
        # Add branding at bottom of sidebar
        st.markdown("---")
        st.markdown("<div style='text-align: center; color: #888;font-size: 24px; font-weight: bold; '>Created by </div>", unsafe_allow_html=True)
        st.markdown("<div style='text-align: center; color: #888;font-size: 24px; font-weight: bold; '> Shadab Siddiqui</div>", unsafe_allow_html=True)
        
    
    # Tabs
    tab0, tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Dashboard", "Process Alerts", "Run Agents", "Alert History", "Log", "Settings", "Agent Instructions"])
    
    # Tab 0: Dashboard
    with tab0:
        st.header("Dashboard")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Alerts Processed", len(st.session_state['alert_history']))
        with col2:
            real_threats = sum(1 for h in st.session_state['alert_history'] if h["analysis"]["classification"] == "Real Threat")
            st.metric("Real Threats", real_threats)
        with col3:
            unresolved = sum(1 for h in st.session_state['alert_history'] if h["analysis"]["triage_status"] == "Fix in Progress")
            st.metric("Unresolved Issues", unresolved)
        st.subheader("Recent Alerts")
        if st.session_state['alert_history']:
            # Handle missing timestamp with fallback
            df = pd.DataFrame([
                {"Content": h["alert"]["content"], 
                 "Classification": h["analysis"]["classification"], 
                 "Severity": h["analysis"].get("severity", "Low"),  # Fallback for severity
                 "Timestamp": h["analysis"].get("timestamp", "N/A")}  # Fallback for timestamp
                for h in st.session_state['alert_history'][-5:]
            ])
            st.dataframe(df, use_container_width=True)
        else:
            st.write("No recent alerts.")
    
    # Tab 1: Process Alerts
    with tab1:
        st.header("Process Alerts")
        cron_interval = st.number_input("Cron Interval (seconds)", min_value=1, value=30, key="cron_interval")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("Process Sample Alerts", key="sample_button"):
                with st.spinner("Processing sample alerts..."):
                    # Check if API keys are available
                    if not check_api_keys(st.session_state['settings']):
                        st.error("API keys required. Please set your API keys in the Settings tab.")
                        return
                        
                    results = process_sample_alerts()
                st.session_state['sample_results'] = results
                st.success("Sample alerts processed.")
        
        with col2:
            if st.button("Fetch Slack Alerts", key="slack_button"):
                with st.spinner(f"Fetching from {st.session_state['settings']['SOURCE_CHANNEL_ID']}..."):
                    # Check if API keys are available
                    if not check_api_keys(st.session_state['settings']):
                        st.error("API keys required. Please set your API keys in the Settings tab.")
                        return
                        
                    results = run_scheduled_task(st.session_state['settings']['SOURCE_CHANNEL_ID'])
                st.session_state['slack_results'] = results
                st.success("Slack alerts fetched and processed.")
        
        with col3:
            if st.button("Process All Slack Alerts", key="all_slack_button"):
                with st.spinner(f"Fetching and processing all from {st.session_state['settings']['SOURCE_CHANNEL_ID']}..."):
                    # Check if API keys are available
                    if not check_api_keys(st.session_state['settings']):
                        st.error("API keys required. Please set your API keys in the Settings tab.")
                        return
                        
                    alerts = fetch_slack_alerts(st.session_state['settings']['SOURCE_CHANNEL_ID'])
                    if not alerts:
                        st.warning("No alerts found.")
                    else:
                        results = [process_alert(alert) for alert in alerts]
                        st.session_state['all_slack_results'] = [{"alert": a, "analysis": r, "source": "Slack"} for a, r in zip(alerts, results)]
                        st.success(f"Processed {len(alerts)} Slack alerts.")
        
        with col4:
            if st.button("Start Cron" if not st.session_state['cron_running'] else "Stop Cron", key="cron_button"):
                st.session_state['cron_running'] = not st.session_state['cron_running']
            if st.session_state['cron_running']:
                st.info(f"Running every {cron_interval} seconds...")
                progress_container = st.empty()
                with st.spinner("Processing..."):
                    results = run_scheduled_task(st.session_state['settings']['SOURCE_CHANNEL_ID'])
                    st.session_state['cron_results'] = results
                    if 'cron_progress' in st.session_state:
                        progress_container.write(st.session_state['cron_progress'])
                    time.sleep(cron_interval)
                    st.rerun()  # Rerun to simulate continuous cron

        # Filterable Results Table
        st.subheader("All Results")
        all_results = []
        for key in ['sample_results', 'slack_results', 'all_slack_results', 'cron_results']:
            if key in st.session_state and st.session_state[key]:
                all_results.extend(st.session_state[key])
        if all_results:
            df = pd.DataFrame([
                {
                    "Source": r["source"],
                    "Content": r["alert"]["content"],
                    "Classification": r["analysis"]["classification"],
                    "Confidence": f"{r['analysis']['confidence']}%",
                    "Triage Status": r["analysis"]["triage_status"],
                    "Correlation": r["analysis"]["correlation"],
                    "Remediation": r["analysis"]["remediation"],
                    "Severity": r["analysis"].get("severity", "Low"),  # Fallback for severity
                    "Timestamp": r["analysis"].get("timestamp", "N/A")  # Fallback for timestamp
                } for r in all_results
            ])
            source_filter = st.multiselect("Filter by Source", options=df["Source"].unique(), default=df["Source"].unique())
            severity_filter = st.multiselect("Filter by Severity", options=df["Severity"].unique(), default=df["Severity"].unique())
            filtered_df = df[df["Source"].isin(source_filter) & df["Severity"].isin(severity_filter)]
            st.dataframe(filtered_df, use_container_width=True)
            if st.button("Clear Results", key="clear_results"):
                for key in ['sample_results', 'slack_results', 'all_slack_results', 'cron_results']:
                    if key in st.session_state:
                        del st.session_state[key]
                st.success("Results cleared.")
        else:
            st.write("No results yet.")
    
    # Tab 2: Run Agents
    with tab2:
        st.header("Run Individual Agents")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            if st.button("Run Classifier", key="classifier_button"):
                with st.spinner("Running..."):
                    try:
                        # Check if API keys are available
                        if not check_api_keys(st.session_state['settings']):
                            st.error("API keys required. Please set your API keys in the Settings tab.")
                            return
                            
                        alert_json = json.loads(custom_alert)
                        output = classifier_agent.run({"role": "user", "content": custom_alert}, response_format=Classification)
                        classification_text = output.content
                        classification = "Unknown"
                        confidence = 0
                        if "Real Threat" in classification_text:
                            classification = "Real Threat"
                        elif "False Positive" in classification_text:
                            classification = "False Positive"
                        elif "Low Priority" in classification_text:
                            classification = "Low Priority"
                        for pattern in [r'confidence (\d+)', r'confidence: (\d+)', r'(\d+)%', r'(\d+) percent']:
                            match = re.search(pattern, classification_text, re.IGNORECASE)
                            if match:
                                confidence = int(match.group(1))
                                break
                        if confidence == 0:
                            if "high confidence" in classification_text.lower():
                                confidence = 85
                            elif "medium confidence" in classification_text.lower():
                                confidence = 65
                            elif "low confidence" in classification_text.lower():
                                confidence = 40
                        st.session_state['classifier_output'] = {
                            "Raw Output": classification_text,
                            "Parsed": {"Classification": classification, "Confidence": f"{confidence}%"}
                        }
                    except json.JSONDecodeError:
                        st.error("Invalid JSON format")
        
        with col2:
            if st.button("Run Triage", key="triage_button"):
                with st.spinner("Running..."):
                    try:
                        # Check if API keys are available
                        if not check_api_keys(st.session_state['settings']):
                            st.error("API keys required. Please set your API keys in the Settings tab.")
                            return
                            
                        alert_json = json.loads(custom_alert)
                        classification = {"classification": "Real Threat", "confidence": 85}
                        output = triage_agent.run({"role": "user", "content": str({"alert": alert_json, "classification": classification["classification"], "confidence": classification["confidence"]})}, response_format=Triage)
                        triage_text = output.content
                        triage_status = "Fix in Progress"
                        if "Suspicious" in triage_text:
                            triage_status = "Suspicious"
                        elif "Resolved" in triage_text:
                            triage_status = "Resolved"
                        elif "Fix in Progress" in triage_text:
                            triage_status = "Fix in Progress"
                        else:
                            triage_status = triage_text.strip().split('\n')[0]
                        st.session_state['triage_output'] = {
                            "Raw Output": triage_text,
                            "Parsed": {"Triage Status": triage_status}
                        }
                    except json.JSONDecodeError:
                        st.error("Invalid JSON format")
        
        with col3:
            if st.button("Run Correlation", key="correlation_button"):
                with st.spinner("Running..."):
                    try:
                        # Check if API keys are available
                        if not check_api_keys(st.session_state['settings']):
                            st.error("API keys required. Please set your API keys in the Settings tab.")
                            return
                            
                        alert_json = json.loads(custom_alert)
                        output = correlation_agent.run({"role": "user", "content": str({"alert": alert_json, "history": st.session_state['alert_history']})}, response_format=Correlation)
                        correlation_text = output.content
                        correlation_info = "No correlations found"
                        if "No correlations found" not in correlation_text and "No correlation" not in correlation_text:
                            correlation_info = correlation_text.strip().split('\n\n')[0]
                        st.session_state['correlation_output'] = {
                            "Raw Output": correlation_text,
                            "Parsed": {"Correlation": correlation_info}
                        }
                    except json.JSONDecodeError:
                        st.error("Invalid JSON format")
        
        with col4:
            if st.button("Run Remediation", key="remediation_button"):
                with st.spinner("Running..."):
                    try:
                        # Check if API keys are available
                        if not check_api_keys(st.session_state['settings']):
                            st.error("API keys required. Please set your API keys in the Settings tab.")
                            return
                            
                        alert_json = json.loads(custom_alert)
                        sample_input = {"alert": alert_json, "classification": "Real Threat", "confidence": 85, "triage_status": "Suspicious", "correlation": "No correlations found"}
                        output = remediation_agent.run({"role": "user", "content": str(sample_input)}, response_format=Remediation)
                        remediation_text = output.content
                        remediation_steps = remediation_text.strip().split('\n\n')[0] if remediation_text else "No specific remediation recommended"
                        st.session_state['remediation_output'] = {
                            "Raw Output": remediation_text,
                            "Parsed": {"Remediation": remediation_steps}
                        }
                    except json.JSONDecodeError:
                        st.error("Invalid JSON format")
        
        # Run All Agents Button
        if st.button("Run All Agents", key="run_all_button"):
            with st.spinner("Running all agents..."):
                try:
                    # Check if API keys are available
                    if not check_api_keys(st.session_state['settings']):
                        st.error("API keys required. Please set your API keys in the Settings tab.")
                        return
                        
                    alert_json = json.loads(custom_alert)
                    # Classifier
                    output = classifier_agent.run({"role": "user", "content": custom_alert}, response_format=Classification)
                    classification_text = output.content
                    classification = "Unknown"
                    confidence = 0
                    if "Real Threat" in classification_text:
                        classification = "Real Threat"
                    elif "False Positive" in classification_text:
                        classification = "False Positive"
                    elif "Low Priority" in classification_text:
                        classification = "Low Priority"
                    for pattern in [r'confidence (\d+)', r'confidence: (\d+)', r'(\d+)%', r'(\d+) percent']:
                        match = re.search(pattern, classification_text, re.IGNORECASE)
                        if match:
                            confidence = int(match.group(1))
                            break
                    if confidence == 0:
                        if "high confidence" in classification_text.lower():
                            confidence = 85
                        elif "medium confidence" in classification_text.lower():
                            confidence = 65
                        elif "low confidence" in classification_text.lower():
                            confidence = 40
                    st.session_state['classifier_output'] = {
                        "Raw Output": classification_text,
                        "Parsed": {"Classification": classification, "Confidence": f"{confidence}%"}
                    }
                    # Triage
                    output = triage_agent.run({"role": "user", "content": str({"alert": alert_json, "classification": classification, "confidence": confidence})}, response_format=Triage)
                    triage_text = output.content
                    triage_status = "Fix in Progress"
                    if "Suspicious" in triage_text:
                        triage_status = "Suspicious"
                    elif "Resolved" in triage_text:
                        triage_status = "Resolved"
                    elif "Fix in Progress" in triage_text:
                        triage_status = "Fix in Progress"
                    else:
                        triage_status = triage_text.strip().split('\n')[0]
                    st.session_state['triage_output'] = {
                        "Raw Output": triage_text,
                        "Parsed": {"Triage Status": triage_status}
                    }
                    # Correlation
                    output = correlation_agent.run({"role": "user", "content": str({"alert": alert_json, "history": st.session_state['alert_history']})}, response_format=Correlation)
                    correlation_text = output.content
                    correlation_info = "No correlations found"
                    if "No correlations found" not in correlation_text and "No correlation" not in correlation_text:
                        correlation_info = correlation_text.strip().split('\n\n')[0]
                    st.session_state['correlation_output'] = {
                        "Raw Output": correlation_text,
                        "Parsed": {"Correlation": correlation_info}
                    }
                    # Remediation
                    sample_input = {"alert": alert_json, "classification": classification, "confidence": confidence, "triage_status": triage_status, "correlation": correlation_info}
                    output = remediation_agent.run({"role": "user", "content": str(sample_input)}, response_format=Remediation)
                    remediation_text = output.content
                    remediation_steps = remediation_text.strip().split('\n\n')[0] if remediation_text else "No specific remediation recommended"
                    st.session_state['remediation_output'] = {
                        "Raw Output": remediation_text,
                        "Parsed": {"Remediation": remediation_steps}
                    }
                    st.success("All agents executed.")
                except json.JSONDecodeError:
                    st.error("Invalid JSON format")
        
        # Detailed Agent Outputs (Grid Layout)
        st.subheader("Agent Outputs")
        cols = st.columns(4)
        for i, (agent, key) in enumerate([
            ("Classifier", "classifier_output"),
            ("Triage", "triage_output"),
            ("Correlation", "correlation_output"),
            ("Remediation", "remediation_output")
        ]):
            with cols[i]:
                if key in st.session_state:
                    with st.expander(f"{agent} Output", expanded=True):
                        st.write("**Raw Output:**", st.session_state[key]["Raw Output"])
                        parsed_df = pd.DataFrame([st.session_state[key]["Parsed"]])
                        st.table(parsed_df)

    # Tab 3: Alert History
    with tab3:
        st.header("Alert History")
        if st.session_state['alert_history']:
            # Backfill missing timestamp and severity for old entries
            updated_history = []
            for entry in st.session_state['alert_history']:
                analysis = entry["analysis"]
                if "timestamp" not in analysis:
                    analysis["timestamp"] = time.ctime()  # Use current time as fallback
                if "severity" not in analysis:
                    threshold = st.session_state['settings'].get('SEVERITY_THRESHOLD', 80)
                    severity = "Low"
                    if analysis["classification"] == "Real Threat" and analysis["confidence"] >= threshold:
                        severity = "High"
                    elif analysis["classification"] == "Real Threat" or analysis["confidence"] >= 50:
                        severity = "Medium"
                    analysis["severity"] = severity
                updated_history.append({"alert": entry["alert"], "analysis": analysis})
            st.session_state['alert_history'] = updated_history
            save_data(HISTORY_FILE, st.session_state['alert_history'])
            
            history_df = pd.DataFrame([
                {
                    "Content": entry["alert"]["content"],
                    "Classification": entry["analysis"]["classification"],
                    "Confidence": entry["analysis"]["confidence"],
                    "Triage Status": entry["analysis"]["triage_status"],
                    "Correlation": entry["analysis"]["correlation"],
                    "Remediation": entry["analysis"]["remediation"],
                    "Severity": entry["analysis"].get("severity", "Low"),  # Fallback for severity
                    "Timestamp": entry["analysis"].get("timestamp", "N/A")  # Fallback for timestamp
                } for entry in st.session_state['alert_history']
            ])
            st.dataframe(history_df, use_container_width=True)
            if st.button("Export History"):
                history_df.to_csv("alert_history.csv", index=False)
                st.success("Exported to alert_history.csv")
            if st.button("Clear History"):
                st.session_state['alert_history'] = []
                save_data(HISTORY_FILE, st.session_state['alert_history'])
                st.success("History cleared.")
        else:
            st.write("No alerts in history.")
    
    # Tab 4: Log
    with tab4:
        st.header("Log")
        st.text_area("Log Output", value="\n".join(st.session_state['log']), height=300)
        if st.button("Clear Log"):
            st.session_state['log'] = []
            st.success("Log cleared.")
    
    # Tab 5: Settings
    with tab5:
        st.header("Settings")
        settings = st.session_state['settings']
        st.info("API keys are required to run tasks. The app will load without them, but you'll need to set them to use the agents.")
        settings["OPENAI_API_KEY"] = st.text_input("OpenAI API Key", value=settings["OPENAI_API_KEY"], type="password")
        settings["GOOGLE_API_KEY"] = st.text_input("Google API Key", value=settings["GOOGLE_API_KEY"], type="password")
        settings["SLACK_TOKEN"] = st.text_input("Slack Token", value=settings["SLACK_TOKEN"], type="password")
        settings["SOURCE_CHANNEL_ID"] = st.text_input("Source Channel ID", value=settings["SOURCE_CHANNEL_ID"])
        settings["ALERT_CHANNEL_ID"] = st.text_input("Alert Channel ID", value=settings["ALERT_CHANNEL_ID"])
        settings["SEVERITY_THRESHOLD"] = st.number_input("Severity Threshold (confidence %)", min_value=0, max_value=100, value=settings.get("SEVERITY_THRESHOLD", 80))
        if st.button("Save Settings"):
            st.session_state['settings'] = settings
            save_data(SETTINGS_FILE, settings)
            global slack_client
            slack_client = WebClient(token=settings["SLACK_TOKEN"])
            update_agents(st.session_state['agent_instructions'], settings)
            st.success("Settings saved and agents updated.")
    
    # Tab 6: Agent Instructions
    with tab6:
        st.header("Update Agent Instructions")
        instructions = st.session_state['agent_instructions']
        instructions["classifier"] = st.text_area("Classifier Instructions", value=instructions["classifier"], height=150)
        instructions["triage"] = st.text_area("Triage Instructions", value=instructions["triage"], height=150)
        instructions["correlation"] = st.text_area("Correlation Instructions", value=instructions["correlation"], height=150)
        instructions["remediation"] = st.text_area("Remediation Instructions", value=instructions["remediation"], height=150)
        if st.button("Update Agents"):
            st.session_state['agent_instructions'] = instructions
            update_agents(instructions, st.session_state['settings'])
            st.success("Agent instructions updated and agents reinitialized.")

if __name__ == "__main__":
    main()