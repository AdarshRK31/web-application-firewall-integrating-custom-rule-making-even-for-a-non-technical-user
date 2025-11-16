# 🛡️ Web Application Firewall (WAF) – Custom Rule-Based Attack Detection for Non-Technical Users


---

## 📘 **Project Overview**
This project implements a lightweight but powerful **Web Application Firewall (WAF)** designed to allow **non-technical users** to create and manage custom security rules through a simple dashboard.  
It analyzes incoming HTTP requests in real time, detects malicious payloads (SQL Injection, XSS, LFI, RCE, etc.), blocks them dynamically, and provides a comprehensive **real-time analytics dashboard** with alerts, logs, statistics, and attack summaries.

This WAF serves as a secure middleware layer protecting any Flask-based web application.

---

## ❗ **Problem Statement**
Most existing WAF solutions require deep technical expertise, complex configuration, and command-line knowledge.  
Small businesses, students, and non-technical administrators cannot easily configure or maintain such systems.

There is a need for a **simple, visually intuitive, non-technical-friendly** WAF that:

- Allows users to create rules without writing code  
- Automatically detects attacks using real-world signatures  
- Provides clear dashboards and alerts  
- Logs all suspicious activity  
- Works out-of-the-box with minimal setup  

This project solves exactly that.

---

## 🔍 **Novelty of the Project**
What makes this WAF different?

### 🌟 **1. Built Specifically for Non-Technical Users**
Most WAFs are technical and require expertise.  
Our system allows **anyone**, even without programming knowledge, to create rules using:

✔ Plain keywords  
✔ Simple regex  
✔ UI-based rule builder  
✔ Toggle-based configuration  

### 🌟 **2. Real-Time Detection + Real-Time Alerts**
Unlike simple logging WAFs, this project includes:

- Real-time Server-Sent Events (SSE)
- Live alert cards on dashboard
- Optional alert sound
- Repeated-attack correlation engine

### 🌟 **3. Built-in Attack Pattern Library**
Automatically detects:
- SQLi  
- XSS  
- LFI/RFI  
- RCE  
- Directory traversal  
- Command injection  

### 🌟 **4. Simulation Engine**
The `/simulate_attack` endpoint generates real attack payloads for testing the system instantly.

### 🌟 **5. Extensible, Modular, and Lightweight**
Designed to be plug-and-play with any Flask project.

---

## 🚀 **Features of the Project**
### 🔐 **Security Features**
- Custom rule builder (regex + keyword based)
- Request interceptor middleware
- Real-time WAF engine
- Built-in attack signature library
- Dynamic blocking, alerting, or allowing
- Repeated attack correlation analysis

### 📊 **Dashboard Features**
- Real-time alerts (SSE)
- Audio alerts (optional)
- Live statistics (top IPs, attack types, trends)
- Export logs as CSV
- Paginated logs with search & filter
- Rule management interface

### 🧪 **Testing Tools**
- Attack simulation engine
- curl/Postman support
- Real-time log viewer

---

## 🛠️ **Tools & Technologies Used**
### **Backend**
- Python 3.x  
- Flask  
- Flask-SQLAlchemy  
- Flask-Mail (optional alerts)

### **Frontend**
- HTML, CSS, JavaScript  
- Bootstrap  
- AJAX + Fetch APIs  
- Server-Sent Events (SSE)

### **Database**
- SQLite / MySQL  
- SQLAlchemy ORM

### **Security Layer**
- Regex-based detection  
- Built-in attack signatures  
- Custom rule builder  

### **Other Tools**
- Postman  
- curl  
- Redis (optional for rule caching)  

---

## 🏗️ **Architecture Overview**


                 ┌──────────────────────┐
                 │      User Browser     │
                 └──────────┬───────────┘
                            │
                            ▼
               ┌────────────────────────┐
               │   Dashboard (HTML/JS)   │
               │   Real-time alerts      │
               └──────────┬──────────────┘
                            │ AJAX/SSE
                            ▼
              ┌─────────────────────────┐
              │        Flask API         │
              │  routes.py (REST + UI)   │
              └───────────┬─────────────┘
                          │
                          ▼
     ┌───────────────────────────────────────────────┐
     │                 WAF Engine                    │
     │                detector.py                    │
     │   - Custom Rules                              │
     │   - Built-In Attack Patterns                  │
     │   - Severity + Correlation Engine             │
     └──────────────────┬────────────────────────────┘
                         │
                         ▼
               ┌───────────────────────────┐
               │   Database (SQLite/MySQL) │
               │ Rules | Logs | Patterns   │
               └───────────────────────────┘



---

## 📅 **Project Phases**

# **Phase 1 – Core WAF Implementation**

| Day | Module / Focus | Tasks to Complete | Languages & Tools | Deliverables |
|-----|----------------|------------------|------------------|--------------|
| 1 | Project Setup | Create project folder, install Flask, initialize Git | Python, Flask, pip, Git | Working Hello World |
| 2 | Database Design | Create tables (rules, logs), SQL schema, DB connect | SQLite/MySQL, SQLAlchemy | Insert/read success |
| 3 | API Skeleton | Implement `/add_rule`, `/delete_rule`, `/logs` | Flask REST, Postman | Working APIs |
| 4 | WAF Core Setup | Create `before_request` interceptor | Flask | Basic blocking works |
| 5 | DB Integration | Fetch rules dynamically, apply matching | Flask + SQLAlchemy | DB-powered rules |
| 6 | Frontend UI | Rule builder page | HTML, JS, Bootstrap | Rule creation UI |
| 7 | Rule & Log UI | Display rules and logs | HTML, Flask templates | Dashboard pages |
| 8 | Integration & Testing | Full system connection test | Python, Postman | End-to-End working |
| 9 | Polishing + Demo | Final testing and documentation | Python, Docs | Working prototype |

---

# **Phase 2 – Advanced Features & Real-World Attack Detection**

| Day | Module / Focus | Status | Comments |
|-----|----------------|--------|----------|
| 10 | Enhanced Rule Builder & Legibility | ✅ Completed | Regex rules, input validation, action types |
| 11 | Real Attack Payload Database | ✅ Completed | SQLi, XSS, CSRF, LFI, RCE patterns added |
| 12 | Input Validation & Sanitization | ✅ Completed | Secure forms & backend sanitization |
| 13 | Logging & Analytics | ✅ Completed | Full dashboard + export |
| 14 | Real-Time Attack Detection Engine | ✅ Completed | Middleware + real patterns |
| 15 | Notifications & Alerts | 🔄 **In Progress** | Real-time SSE + alert sound |
| 16 | Rule Optimization & Interface | 🔄 In Progress | GUI improvements + caching |

---

## ✔️ **Current Status**
You have completed **55% of the project**.  
Remaining tasks (Day 15 finalization + Day 16 optimization) 

---
