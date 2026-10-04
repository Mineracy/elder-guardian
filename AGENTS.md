# System Requirements Specification: Anti-Scam Guardian Agent

## 1. System Overview & Objective
The Guardian Agent is an intervention system designed to protect vulnerable individuals from financial scams and phishing attacks[cite: 1]. The system uses a Manifest V3 Chrome Extension to monitor web activity[cite: 1], intercepting risky actions[cite: 1]. It communicates with a **Hono JS backend** to trigger an approval request to a designated trusted contact via email[cite: 1, 2]. If the action is denied or flagged, an orchestrated **Gemini AI Agent** generates an empathetic, educational breakdown of the threat for the user[cite: 1] and a natural alert for the trusted contact.

## 2. Architecture & Components
*   **Client (Chrome Extension)**: Monitors visited URLs and link clicks[cite: 1]. Halts navigation when an anomaly is detected[cite: 1], routing control to the backend.
*   **Backend (Hono JS & Cloudflare Workers)**: Lightweight API handling user authentication, policy rules (whitelist checks)[cite: 1], and intervention state management[cite: 2].
*   **Database (Cloudflare D1 / SQLite)**: Stores user credentials, contact pairings, and intervention logs.
*   **Safety Agent (Gemini API)**: An orchestrated LLM workflow that evaluates the threat and generates tailored dual-communications (user coaching and Elder Guardian alerts)[cite: 1].

## 3. Data Storage & Authentication (SQLite)

### Schema Requirements
The Cloudflare D1 SQLite database must implement the following core tables:
*   `users`: Stores `id`, `email`, hashed passwords, and `role` (`protected` or `trusted`).
*   `contact_pairings`: Links a `protected` user account to a `trusted` contact email[cite: 1, 2].
*   `whitelist_domains`: Stores allowed domains mapped to specific users[cite: 1].
*   `intervention_requests`: Tracks blocked events (`target_url`, `threat_level`, `user_education_message`, `status`) and resolution state (`pending`, `allowed`, `denied`).

### Auth Requirements
*   **Sign Up / Sign In**: Handled via the extension popup interface[cite: 2]. The backend will hash passwords (e.g., using Web Crypto API SHA-256) and return a secure session token.
*   **Pairing**: Links a `protected` user account to a `trusted` contact[cite: 1, 2].

## 4. AI Agent Orchestration (Gemini API)
When suspicious activity is detected, the Hono backend passes the event context to the Gemini API. The orchestration must follow these best practices:

*   **API Key Management**: The `GEMINI_API_KEY` must be securely stored as an environment variable (Cloudflare Worker Secret).
*   **Structured JSON Output**: The agent must be constrained using `responseSchema` to guarantee a predictable JSON response containing:
    *   `threat_level`: Categorized severity.
    *   `risk_summary`: Technical breakdown of the threat.
    *   `user_education_message`: An empathetic, non-judgmental explanation teaching the user why the action was dangerous and what signs to watch for[cite: 1].
    *   `trusted_contact_alert`: A natural-sounding email/alert drafted for the trusted contact[cite: 2].
*   **Deterministic Guardrails**: Set a low temperature (e.g., 0.2) to ensure consistent, non-hallucinated safety evaluations.
*   **Graceful Fallbacks**: If the Gemini API times out or fails, the system must default to a hardcoded "Medium Risk" response that pauses the link and alerts the contact anyway.

## 5. Functional Requirements

### 5.1 Client Browser Extension (Manifest V3)
*   **Detection Engine**: Match the active tab domain against the `whitelist_domains`[cite: 1]. 
*   **Hold & Intercept**: When flagged, pause the requested action and transition the browser tab to a holding state ("Awaiting verification")[cite: 1, 2]. Send payload to the Hono backend.
*   **Resolution Listener**: If allowed, release the hold[cite: 2]. If denied, display the AI-generated `user_education_message` on the redirect interface[cite: 1].

### 5.2 Intervention & Notification Service
*   **Trigger**: On a new intervention request, the backend executes the Gemini threat analysis.
*   **Email Notification**: Deliver an email to the trusted contact containing the AI-generated `trusted_contact_alert` and a secure review link[cite: 2].
*   **Trusted Contact Interface**: A web interface displaying the risk explanation and two prominent actions: `[Allow]` and `[Deny]`[cite: 2].

### 5.3 Educational Safety Agent (Denial Flow)
*   **Trigger**: Activated immediately when the trusted contact selects `[Deny]`[cite: 1, 2], or directly upon interception.
*   **Delivery**: The extension updates the blocked tab to display the empathetic AI explanation, focusing on actionable future prevention without using condescending language[cite: 1].