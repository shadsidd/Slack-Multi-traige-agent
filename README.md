# Slack Multi-triage Agent

A powerful Streamlit-based application for automated alert triage and analysis using Agno agents and LLM models.

![Slack Multi-triage Agent](https://img.shields.io/badge/version-1.0.0-blue)


## Overview

This application provides an automated triage system for security alerts from Slack channels. It uses Agno agents powered by LLM models (OpenAI or Google Gemini) to classify, triage, correlate, and suggest remediation steps for security alerts.

## Features

- **Multi-agent Architecture**: Utilizes specialized agents for classification, triage, correlation, and remediation
- **Slack Integration**: Fetches alerts from Slack channels and posts results back
- **Real-time Processing**: Process alerts individually or in batch
- **Scheduled Monitoring**: Cron-like functionality to continuously monitor Slack channels
- **Interactive Dashboard**: Visualize alert metrics and processing history
- **Customizable Settings**: Configure API keys, channels, and agent instructions
- **Persistent Storage**: Saves alert history and settings between sessions

## Demo
https://slack-auto-triage-alerts.streamlit.app/

## Requirements

```
python-dotenv==1.0.0
slack-sdk==3.26.1
agno==0.1.0
streamlit==1.32.0
pandas==2.1.4
pydantic==2.5.2
```

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Slack-Multi-traige-agent.git
   cd Slack-Multi-traige-agent
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your API keys:
   ```
   OPENAI_API_KEY=your_openai_api_key
   GOOGLE_API_KEY=your_google_api_key
   SLACK_TOKEN=your_slack_bot_token
   ```

## Usage

1. Start the application:
   ```bash
   streamlit run "app.py"
   ```

2. Configure your settings in the "Settings" tab:
   - Enter your API keys
   - Set your Slack channel IDs
   - Adjust the severity threshold

3. Use the application:
   - **Dashboard**: View metrics and recent alerts
   - **Process Alerts**: Process sample alerts or fetch from Slack
   - **Run Agents**: Test individual agents with custom alerts
   - **Alert History**: View and export processed alerts
   - **Log**: Monitor application logs
   - **Settings**: Configure application parameters
   - **Agent Instructions**: Customize agent behavior

## Agent Capabilities

### Classifier Agent
Analyzes alert content and metadata to classify alerts as:
- Real Threat
- False Positive
- Low Priority

### Triage Agent
Assigns triage status based on classification and confidence:
- Suspicious (for high-confidence real threats)
- Resolved (for low priority or false positives)
- Fix in Progress (for other cases)

### Correlation Agent
Identifies patterns between current and historical alerts.

### Remediation Agent
Suggests specific remediation steps based on alert context.

## Architecture

The application follows a modular architecture:
- **UI Layer**: Streamlit-based interface
- **Agent Layer**: Agno agents for specialized tasks
- **Data Layer**: JSON-based persistent storage
- **Integration Layer**: Slack API integration

## Development

### Adding New Features

1. Extend the agent instructions in the `agent_instructions` dictionary
2. Add new processing functions in the core functions section
3. Update the UI to expose new functionality

### Customizing Agent Behavior

Modify the agent instructions in the "Agent Instructions" tab to change how agents interpret and process alerts.
