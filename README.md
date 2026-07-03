# 🛡️ TraceHost

<div align="center">

**A domain intelligence and security analysis platform for detecting malicious domains, scoring risk, and visualizing threat data.**

[![Next.js](https://img.shields.io/badge/Next.js-black?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Django](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white)](https://www.djangoproject.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)

</div>

TraceHost is a monorepo: a **Next.js** frontend for exploring domain analysis results and a **Django REST** backend that performs the actual lookups (WHOIS, DNS, geolocation, Shodan, SecurityTrails) and computes a composite risk score, with scan history and flagged domains persisted in **MongoDB Atlas**.

## ✨ Features

- 🔍 **Domain Analysis** — WHOIS, DNS resolution, and IP geolocation lookups for a target domain
- 🧮 **Risk Scoring Engine** (`Backend/checker/risk_engine.py`) — computes an advanced composite risk score from multiple signals
- 🦠 **Threat Intelligence** (`Backend/checker/threat_intel.py`) — Shodan exposed-service data and SecurityTrails history combined into a threat summary
- 🤖 **AI Risk Summaries** — OpenRouter (default model `openai/gpt-oss-120b:free`) generates a human-readable summary of scan findings
- 🌎 **Geolocation Visualization** — server locations plotted via the Google Maps API
- 🗃️ **Persistent Scan History** — every scan, flagged domain, and dashboard stat is stored in MongoDB
- 🚩 **Suspicious Domain Tracking** — list, flag, and review domains marked as suspicious
- 📊 **Dashboard** — aggregate stats across all scans
- 📑 **PDF Export** — export a domain's analysis results as a report
- 🎨 **Minimalist UI** — clean, modern interface built with Tailwind CSS, Radix UI, and shadcn-style components

## 📂 Project Structure

```
TraceHost/
├── Frontend/                       # Next.js (App Router) frontend
│   ├── app/
│   │   ├── page.tsx                 # Home page
│   │   ├── analyze/                 # Domain analysis pages (+ [domain] detail, results)
│   │   ├── suspicious/              # Suspicious domains listing
│   │   ├── api-docs/                # In-app API documentation
│   │   └── api/                     # Next.js route handlers
│   ├── components/
│   │   ├── analyze/                  # Analysis + risk-breakdown UI
│   │   ├── common/                   # Search bar, API status indicator, etc.
│   │   ├── layout/                   # Header/layout components
│   │   ├── pdf/                      # PDF report viewer/export
│   │   └── ui/                       # Base UI primitives (Radix/shadcn-based)
│   ├── lib/
│   │   ├── api.ts                    # Backend API client
│   │   ├── utils.ts
│   │   └── hooks/use-media-query.ts
│   └── public/                       # Static assets
│
├── Backend/                        # Django REST backend
│   ├── website_checker/             # Django project (settings, root URLs, WSGI/ASGI)
│   ├── project/                     # API URL routing + custom error handlers
│   └── checker/                     # Main app
│       ├── views.py                  # API endpoint handlers
│       ├── risk_engine.py            # Composite risk-scoring logic
│       ├── threat_intel.py           # Shodan / SecurityTrails aggregation
│       ├── mongo_store.py            # MongoDB Atlas persistence layer
│       └── models.py / tests.py / …
│
├── start-dev.sh                    # Boots Django (:8000) + Next.js (:3000) together
├── .env.example                    # Reference for all required environment variables
└── DOCUMENTATION.md                # Extended developer documentation
```

## 🚀 Getting Started

### Prerequisites

- 📦 **Node.js** 18.x or higher and **npm**
- 🐍 **Python** 3.10+ and `pip`
- 🍃 A **MongoDB Atlas** connection string (or any MongoDB instance)
- API keys for: **ipinfo.io**, **Shodan**, **SecurityTrails**, and **OpenRouter** (see [Environment Configuration](#️-environment-configuration))

### 🔧 Quick start (both servers)

The included script installs dependencies, applies Django migrations, and starts both servers in one step:

```bash
git clone https://github.com/Atharva-Dhavale/TraceHost.git
cd TraceHost
./start-dev.sh
```

- Backend (Django) → [http://localhost:8000](http://localhost:8000)
- Frontend (Next.js) → [http://localhost:3000](http://localhost:3000)
- Logs are written to `logs/django.log` and `logs/nextjs.log`

### 🔧 Manual setup

#### 1️⃣ Backend (Django)
```bash
cd Backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp ../.env.example .env         # then fill in MONGO_URI, IPINFO_API_KEY, SHODAN_API_KEY,
                                 # SECURITY_TRAILS_API_KEY, OPENROUTER_API_KEY

python3 manage.py migrate
python3 manage.py runserver     # http://localhost:8000
```

#### 2️⃣ Frontend (Next.js)
```bash
cd Frontend
npm install

cp ../.env.example .env.local   # then fill in NEXT_PUBLIC_* values

npm run dev                     # http://localhost:3000
```

### 🧪 Testing & linting

```bash
# Backend
cd Backend && python3 manage.py test

# Frontend
cd Frontend && npm run lint
```

## ⚙️ Environment Configuration

Environment variables are split across two files — see `.env.example` at the repo root for the full reference.

### 🔑 Frontend (`Frontend/.env.local`)

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXT_PUBLIC_GOOGLE_MAPS_API_KEY` | Google Maps API key for location visualization | – |
| `NEXT_PUBLIC_API_URL` | Backend origin (the client appends `/api/...` itself) | `http://localhost:8000` |
| `NEXT_PUBLIC_BACKEND_URL` | Backend server URL | `http://localhost:8000` |
| `NEXT_PUBLIC_API_TOKEN` | Optional bearer token sent with API requests | – |
| `NEXT_PUBLIC_ENABLE_API_LOGGING` | Enable detailed API request logging | `true` |
| `NEXT_PUBLIC_CACHE_TTL` | Client cache duration in seconds | `300` |
| `NEXT_PUBLIC_REQUEST_TIMEOUT` | API request timeout in milliseconds | `120000` |
| `NEXT_PUBLIC_FETCH_TIMEOUT` | Fetch timeout in milliseconds | `10000` |
| `NEXT_PUBLIC_API_CHECK_FREQUENCY` | How often to poll API status (ms) | `30000` |

### 🔒 Backend (`Backend/.env`)

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB Atlas connection string (database name comes from the URI path) |
| `IPINFO_API_KEY` | [ipinfo.io](https://ipinfo.io/) key for IP geolocation |
| `SHODAN_API_KEY` | [Shodan](https://www.shodan.io/) key for exposed-service/port data |
| `SECURITY_TRAILS_API_KEY` | [SecurityTrails](https://securitytrails.com/) key for DNS/subdomain history |
| `OPENROUTER_API_KEY` | [OpenRouter](https://openrouter.ai/) key used to generate the AI risk summary |
| `OPENROUTER_MODEL` | OpenRouter model id to use (default: `openai/gpt-oss-120b:free`) |

## 🌐 API Endpoints

All endpoints are served under `Backend`'s `/api/` prefix (e.g. `http://localhost:8000/api/analyze`):

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET/POST | `/api/analyze` | Run a full domain analysis (WHOIS, DNS, geolocation, threat intel, risk score) |
| GET | `/api/suspicious` | View a single suspicious domain's details |
| GET | `/api/dashboard` | Aggregate dashboard statistics |
| GET | `/api/suspicious_domains` | List all flagged/suspicious domains |
| POST | `/api/flag_domain` | Flag a domain as suspicious |
| GET | `/api/scan_history` | Retrieve past scan history |

## 🌐 Integration with External Services

- **WHOIS** (`python-whois`) — domain registration details
- **DNS** (`dnspython`) — resolution and record validation
- **ipinfo.io** — IP geolocation for mapping server locations
- **Shodan** — exposed services, open ports, banner data
- **SecurityTrails** — historical DNS and subdomain data
- **OpenRouter** — AI-generated natural-language risk summaries (configurable model, defaults to `openai/gpt-oss-120b:free`)
- **MongoDB Atlas** — persistent storage for scans, dashboard stats, and flagged domains

## 🔐 Security Best Practices

1. 🚫 Never commit `.env` or `.env.local` files — both are already covered by `.gitignore`
2. 🔄 Use different API keys and MongoDB databases for development and production
3. 🔁 Regularly rotate API keys and MongoDB credentials
4. 🛡️ Restrict `CORS_ALLOWED_ORIGINS` / `ALLOWED_HOSTS` in `Backend/website_checker/settings.py` before deploying

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Contact

Atharva Dhavale - [GitHub Profile](https://github.com/Atharva-Dhavale)

Project Link: [https://github.com/Atharva-Dhavale/TraceHost](https://github.com/Atharva-Dhavale/TraceHost)
