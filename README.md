# AI SOC Assistant (ChatBot)

## Overview
This project is an AI-powered Security Operations Center (SOC) Assistant built to interface with Wazuh SIEM and OpenSearch. It provides a conversational interface for security analysts to query live SIEM data, investigate alerts, check agent statuses, and summarize findings using a custom LLM (`foundation-sec-8b-instruct`).

## Architecture
The application is structured as a full-stack JavaScript project:
- **Frontend**: React.js (Vite) application handling the user interface, state, and visual data representation.
- **Backend**: Node.js (Express) server acting as an API proxy, orchestrating requests between the frontend, Wazuh Manager API, OpenSearch Indexer, and the LLM API.

### Tech Stack
- **Frontend**: React 19, Vite, Framer Motion (animations), Recharts (data visualization), Lucide React (icons), CSS (styling).
- **Backend**: Node.js, Express, Axios, HTTPS (for secure API communication), dotenv (environment variables).
- **Integrations**: Wazuh Server API, OpenSearch Indexer, Custom LLM API (`foundation-sec-8b-instruct`).

## Directory Structure
```
ChatBot/
├── server/
│   ├── .env               # Environment variables for the backend
│   ├── package.json       # Backend dependencies (express, axios, cors, dotenv)
│   └── server.js          # Main Express server and API logic
├── src/
│   ├── assets/            # Static assets
│   ├── components/        # Reusable React components (ChartCard, DataCard, Sidebar, etc.)
│   ├── context/           # React Context (e.g., ThemeContext)
│   ├── pages/             # Route components (LoginPage, ChatPage)
│   ├── App.jsx            # Main application component routing & guards
│   ├── index.css          # Global styles
│   └── main.jsx           # React entry point
├── package.json           # Frontend dependencies and scripts
├── vite.config.js         # Vite configuration
└── README.md              # Project documentation (this file)
```

## Core Features
- **Conversational Queries**: Ask natural language questions like "Show me brute force attacks in the last 24 hours" or "Check IP 190.03.12.56".
- **Zero-Latency Fast-Path**: Direct conversational responses for standard greetings and help requests without querying the SIEM.
- **Intent & Entity Extraction**: The backend automatically extracts IPv4 addresses, dynamic time windows (e.g., "past 1 hour", "last 7 days"), and operational intents (e.g., agent inventory, vulnerabilities, brute force).
- **Wazuh Agent Management**: Queries the Wazuh Manager API to check agent status (connected, disconnected, active).
- **OpenSearch Integration**: Dynamically builds OpenSearch queries with precise time filters to retrieve SIEM alerts and vulnerabilities from `/wazuh-alerts-*` and `/wazuh-states-vulnerabilities-*`.
- **RAG LLM Summarization**: Employs Retrieval-Augmented Generation (RAG). Extracts accurate log counts and feeds a subset of minified logs (up to 50) to a custom LLM to provide human-readable summaries of security events.
- **Interactive UI**: Includes rich visual elements such as Recharts-based data cards, log detail modals, a terminal feed, and a responsive sidebar.

## Setup & Installation

### Prerequisites
- Node.js (v18+)
- Access to a Wazuh Manager (API port 55000)
- Access to an OpenSearch Indexer (port 9200)
- Access to the LLM API endpoint

### 1. Backend Setup
1. Navigate to the `server/` directory:
   ```bash
   cd server
   ```
2. Install backend dependencies:
   ```bash
   npm install
   ```
3. Configure Environment Variables:
   Create or edit the `.env` file in the `server/` directory with the following variables:
   ```env
   PORT=3002
   OPENSEARCH_URL=https://<opensearch-ip>:9200
   WAZUH_USER=<wazuh-username>
   WAZUH_PASSWORD=<wazuh-password>
   WAZUH_SERVER_API_URL=https://<wazuh-manager-ip>:55000
   LLM_API_URL=https://<llm-api-endpoint>
   ```
4. Start the backend proxy server:
   ```bash
   npm start
   # or npm run dev
   ```

### 2. Frontend Setup
1. Open a new terminal and navigate to the root directory (`ChatBot/`).
2. Install frontend dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```

## API Endpoints (Backend)
- `POST /api/chat`: Main operational endpoint.
  - **Payload**: `{ "text": "user query", "history": [] }`
  - **Response**: Returns a JSON object containing the LLM summary, raw parsed logs, total accurate hit counts, and source execution details.
