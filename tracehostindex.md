# TraceHost - Project File Structure Index

## Overview
TraceHost is a **domain intelligence and security analysis platform** for detecting malicious domains and analyzing security threats. It consists of a **Next.js (TypeScript) frontend** and a **Django (Python) backend** that integrates with multiple external APIs (IPinfo, Shodan, SecurityTrails, Gemini AI) for comprehensive domain analysis.

---

## Root Directory (`TraceHost/`)

| File/Directory | Type | Description |
|---|---|---|
| `README.md` | File | Project documentation with setup instructions, features list, and deployment guide |
| `TROUBLESHOOTING.md` | File | Common troubleshooting steps and solutions |
| `information.md` | File | Additional project information and notes |
| `start-dev.sh` | File | **Automated startup script** — launches both frontend and backend servers together |
| `next.config.js` | File | Root-level Next.js config (likely unused; main config is in Frontend/) |
| `package.json` | File | Root-level package.json (minimal, mostly for monorepo-style scripts) |
| `.gitignore` | File | Git ignore rules for the project |
| `.gitattributes` | File | Git attributes configuration |
| `bfg.jar` | File | BFG Repo-Cleaner tool for removing sensitive data from git history |

---

## Backend (`Backend/`) — Django REST API

The backend is a **Django 4.2+ application** that performs domain analysis using WHOIS, DNS, IPinfo, Shodan, SecurityTrails, and Google Gemini AI APIs.

### Root Files

| File | Description |
|---|---|
| `manage.py` | **Django management script** — Entry point for running the server (`python manage.py runserver`). Uses `website_checker.settings` as the settings module. |
| `requirements.txt` | **Python dependencies** — Django, DRF, django-cors-headers, requests, python-whois, dnspython, ipinfo, shodan, google-generativeai, python-decouple, Pillow |
| `.env.example` | **Environment variable template** — Contains placeholders for SECRET_KEY, API keys (IPINFO, SHODAN, SECURITY_TRAILS, GEMINI), and DB settings |
| `package.json` | Node.js package config (contains `concurrently` for running both servers) |
| `package-lock.json` | Node.js lock file |

### `website_checker/` — Django Project Configuration (Active Settings Module)

| File | Description |
|---|---|
| `__init__.py` | Python package init |
| `settings.py` | **Main Django settings** — Configures INSTALLED_APPS (checker, corsheaders, rest_framework), CORS settings (allow all origins in dev), SQLite database, and caching. This is the active settings file used by `manage.py`. |
| `urls.py` | **Root URL configuration** — Maps `api/` prefix to `checker.urls` and `admin/` to Django admin |
| `wsgi.py` | WSGI application entry point for production deployment |
| `asgi.py` | ASGI application entry point for async deployment |

### `project/` — Alternate Settings Module (NOT actively used by manage.py)

| File | Description |
|---|---|
| `settings.py` | **Alternative settings file** — More production-ready config with decouple-based env vars, logging, REST_FRAMEWORK settings. NOT used by default `manage.py` (which uses `website_checker.settings`). |
| `urls.py` | **Alternative URL config** — Imports `check_domain` (which doesn't exist as that name in views.py — would cause ImportError). NOT used by default. |
| `views.py` | Custom 404/500 JSON error handlers |

### `checker/` — Main Django App

| File | Description |
|---|---|
| `__init__.py` | Python package init |
| `models.py` | **DomainScan model** — Stores domain scan results with fields: domain, ip_address, risk_score, is_suspicious, is_flagged, scan_result (JSON), country, city, registrar, creation/expiration dates, status, notes |
| `views.py` | **Core API logic (1137 lines)** — Contains all view functions: `analyze_domain` (main analysis endpoint), `suspicious_view`, `get_dashboard_data`, `suspicious_domains_list`, `flag_domain`. Also contains helper functions for WHOIS, DNS, ASN, Shodan, SecurityTrails, SSL cert lookups, AI risk scoring via Gemini API, and domain summary generation. |
| `urls.py` | **App URL patterns** — Maps API endpoints: `analyze`, `suspicious`, `dashboard`, `suspicious_domains`, `flag_domain` (plus legacy/alt routes with trailing slashes) |
| `admin.py` | Django admin registration (minimal) |
| `apps.py` | Django app configuration |
| `tests.py` | Test file (minimal) |
| `migrations/` | Database migration files |

### `venv/` and `myvenv/` — Python Virtual Environments

Two virtual environment directories exist. `venv/` appears to be the active one.

---

## Frontend (`Frontend/`) — Next.js 13.5 Application

The frontend is a **Next.js 13 (App Router)** application built with **TypeScript**, **Tailwind CSS**, and **shadcn/ui** components. It provides the user interface for domain analysis, suspicious domain tracking, and security reports.

### Root Configuration Files

| File | Description |
|---|---|
| `package.json` | **Dependencies** — Next.js 13.5.1, React 18.2, Tailwind CSS, shadcn/ui (Radix UI primitives), Recharts, jsPDF, Google Maps loader, Framer Motion, Axios |
| `next.config.mjs` | **Next.js configuration** — Sets `NEXT_PUBLIC_API_URL` default to `http://localhost:8000`, configures image optimization, webpack chunking, security headers, and module transpilation |
| `next.config.js` | Alternate Next.js config (likely overridden by .mjs) |
| `tsconfig.json` | TypeScript configuration with path aliases (`@/` → project root) |
| `tailwind.config.ts` | Tailwind CSS configuration with custom theme extensions |
| `postcss.config.js` | PostCSS configuration for Tailwind |
| `.eslintrc.json` | ESLint configuration |
| `.env.example` | **Frontend env template** — `NEXT_PUBLIC_API_URL` defaults to `http://localhost:5000/api` (NOTE: conflicts with next.config.mjs default of `http://localhost:8000`) |
| `components.json` | shadcn/ui component configuration |
| `.gitignore` | Frontend-specific git ignore rules |
| `next-env.d.ts` | Next.js TypeScript declarations |

### `app/` — Next.js App Router Pages

| File/Directory | Description |
|---|---|
| `layout.tsx` | **Root layout** — Sets up JetBrains Mono font, ThemeProvider (dark mode default), Header, Footer, Toaster for notifications |
| `page.tsx` | **Home page** — Hero section with domain search, feature cards (Threat Detection, Domain Intelligence, Real-time Analysis) |
| `globals.css` | **Global styles** — CSS custom properties, dark theme colors, animations, layout utilities |
| `analyze/page.tsx` | **Analyze page** — Domain analysis form and input |
| `analyze/[domain]/` | Dynamic route for domain-specific analysis |
| `analyze/results/` | Analysis results display page |
| `suspicious/page.tsx` | **Suspicious domains page** — Lists flagged/suspicious domains with filtering |
| `api-docs/page.tsx` | **API documentation page** — Interactive API endpoint documentation |
| `test-pdf/page.tsx` | **PDF test page** — PDF generation/viewing test page |

### `components/` — React Components

#### `components/analyze/` — Analysis Components
| File | Description |
|---|---|
| `domain-form.tsx` | **Domain input form** — Text input + submit button, calls `analyzeDomain()` API, redirects to results page |
| `domain-results.tsx` | **Results display (52KB)** — Large component rendering full analysis results: WHOIS data, DNS info, risk score, server location, AI summary, security analysis |
| `dns-info.tsx` | DNS information display component |
| `google-map.tsx` | Google Maps integration for server location visualization |
| `map-component.tsx` | Map wrapper component |
| `subdomains-list.tsx` | Subdomain enumeration results display |

#### `components/common/` — Shared Components
| File | Description |
|---|---|
| `api-status.tsx` | **API connection status indicator** — Shows colored dot (green/amber/red) indicating backend connectivity. Polls `/health` endpoint every 30s. Currently defaults to `http://localhost:5000` (mismatch with backend on port 8000). |
| `search-domain.tsx` | Reusable domain search input component used on home page |

#### `components/dashboard/` — Dashboard Components
| File | Description |
|---|---|
| `stat-card.tsx` | Statistics card component |
| `recent-scans.tsx` | Recent domain scans list |
| `daily-scans-chart.tsx` | Chart showing daily scan activity |
| `risk-distribution-chart.tsx` | Chart showing risk score distribution |

#### `components/layout/` — Layout Components
| File | Description |
|---|---|
| `header.tsx` | **Main header/navigation** — App logo, navigation links, API status indicator |

#### `components/pdf/` — PDF Components
| File | Description |
|---|---|
| `pdf-viewer.tsx` | PDF report viewer component |

#### `components/ui/` — shadcn/ui Base Components
47 UI component files (accordion, alert, badge, button, card, chart, dialog, dropdown-menu, input, select, tabs, toast, tooltip, etc.) — Standard shadcn/ui library components.

#### `components/theme-provider.tsx`
Next-themes provider wrapper for dark/light mode switching.

### `lib/` — Utility Libraries

| File | Description |
|---|---|
| `api.ts` | **API client (main)** — All fetch calls to backend: `analyzeDomain()`, `flagDomain()`, `getSuspiciousDomains()`, `exportSuspiciousDomains()`, `getDashboardData()`, `getSuspiciousAnalysis()`. Base URL defaults to `http://localhost:8000/api`. |
| `utils.ts` | Utility functions (className merging with clsx + tailwind-merge) |

### `hooks/` — Custom React Hooks

| File | Description |
|---|---|
| `use-toast.ts` | Toast notification hook (based on shadcn/ui toast) |

### `src/` — Legacy/Additional Source Files

| Directory | Description |
|---|---|
| `src/assets/` | Static asset files |
| `src/assets.zip` | Bundled assets archive |
| `src/components/ImageDisplay.js` | Legacy image display component (JSX) |
| `src/components/ImageDisplay.css` | Styles for ImageDisplay |

### `public/` — Static Assets
Publicly served static files (images, icons, favicon).

---

## Key API URL Configuration (Important)

| Source | Default API URL | Notes |
|---|---|---|
| `Frontend/lib/api.ts` (line 4) | `http://localhost:8000/api` | Used for all API calls |
| `Frontend/next.config.mjs` (line 11) | `http://localhost:8000` | Sets NEXT_PUBLIC_API_URL env var |
| `Frontend/components/common/api-status.tsx` (line 15) | `http://localhost:5000` | **MISMATCH** — health check uses wrong port |
| `Frontend/.env.example` (line 2) | `http://localhost:5000/api` | **MISMATCH** — template has wrong port |
| Backend `manage.py` | Runs on port `8000` (default Django) | Default Django dev server port |

---

## Known Issues Identified

1. **Missing `corsheaders` module** — `django-cors-headers` is not installed in the active venv despite being listed in `requirements.txt`
2. **Missing `djangorestframework`** — Also not installed in venv
3. **Port mismatch in `api-status.tsx`** — Defaults to port 5000 instead of 8000
4. **Port mismatch in `.env.example`** — Frontend env example uses port 5000 instead of 8000
5. **`project/` directory uses `check_domain` import** — function is named `analyze_domain` in views.py (ImportError if that settings module were used)
