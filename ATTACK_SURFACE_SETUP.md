# Attack Surface Explorer — Setup Guide

## Overview
Attack Surface Explorer is a new feature that maps a domain's infrastructure (subdomains, IPs, ASNs, countries, SSL certificates) as an interactive graph using Neo4j and React Flow.

## Status: ✅ Functional

### Backend (Django)
- **New App**: `Backend/attack_surface/`
- **Endpoints**:
  - `GET /api/attack-surface/scan?domain=<domain>` — Scans a domain and returns graph (nodes + edges)
  - `GET /api/attack-surface/invalidate?domain=<domain>` — Clears cache for a domain
- **Features**:
  - Redis caching (12-hour TTL, key: `attack_surface:{domain}`)
  - Reuses existing helpers (`enumerate_subdomains`, `get_dns_info`, `get_asn_info`)
  - Concurrent subdomain resolution (max 10 workers)
  - Per-subdomain risk scoring (SSL status, naming patterns, etc.)
  - Neo4j integration (MERGE-based, idempotent writes)
  - Graceful degradation when Neo4j unavailable

### Frontend (Next.js + React)
- **Page**: `/attack-surface`
- **Components**:
  - `attack-surface-search.tsx` — Input form for root domain
  - `graph-canvas.tsx` — React Flow canvas with dagre auto-layout
  - `node-detail-panel.tsx` — Side panel showing node details
- **Features**:
  - Interactive graph with pan, zoom, minimap
  - Custom nodes per type (Domain/Subdomain/IP/ASN/Country/SSL)
  - Click node → side panel with details + connected nodes
  - Responsive dark theme integration
- **Navbar**: Added "Attack Surface" link (desktop + mobile)

## Configuration

### Backend .env
Add/verify these variables in `Backend/.env`:

```env
# Redis (already configured)
REDIS_URL=redis://127.0.0.1:6379/1

# Neo4j Aura (optional — feature gracefully degrades if not set)
NEO4J_URI=neo4j+s://your-database-id.databases.neo4j.io
NEO4J_USER=your-username
NEO4J_PASSWORD=your-password
```

To get Neo4j Aura credentials:
1. Visit https://console.neo4j.io
2. Create a free instance
3. Copy connection URI, username, and password
4. Paste into `.env`

## Running

### Backend
```bash
cd Backend
source venv/bin/activate
python manage.py check  # Verify setup
python manage.py runserver 8000
```

### Frontend
```bash
cd Frontend
npm run dev
# Visit http://localhost:3000/attack-surface
```

## Testing

### Backend Endpoint
```bash
# Test without Neo4j (should work)
curl "http://localhost:8000/api/attack-surface/scan?domain=example.com" | jq

# Expected response:
# {
#   "domain": "example.com",
#   "subdomain_count": 0,  # or N if enumerator returns results
#   "nodes": [...],
#   "edges": [...],
#   "neo4j_persisted": false,  # true once you add Neo4j creds
#   "cached": false
# }
```

### Frontend
1. Navigate to `/attack-surface`
2. Enter a domain (e.g., `google.com`, `microsoft.com`)
3. Click "Scan"
4. Graph should render with nodes and edges
5. Click any node to see details in the side panel

## Known Limitations

- **SecurityTrails Free Tier**: Subdomain enumeration is limited by the free API quota. If exhausted, you'll see `0 subdomains` but the feature still works (returns just the domain node).
- **Neo4j Optional**: Graph persists to Neo4j only if credentials are configured. Without it, the feature still works for visualization.
- **Cached Results**: Cached results are returned from Redis for 12 hours. Use invalidate endpoint to force a fresh scan.

## Files Modified/Created

### Backend
- `Backend/attack_surface/` (new app)
  - `apps.py`
  - `views.py`
  - `urls.py`
  - `services/neo4j_service.py`
  - `services/graph_builder.py`
  - `migrations/`
- `Backend/website_checker/settings.py` (added attack_surface to INSTALLED_APPS, Neo4j config)
- `Backend/website_checker/urls.py` (added attack_surface routes)
- `Backend/requirements.txt` (added neo4j==5.24.0)
- `Backend/.env` (added Neo4j placeholders)

### Frontend
- `Frontend/app/attack-surface/page.tsx` (new page)
- `Frontend/components/attack-surface/` (new components)
  - `attack-surface-graph.tsx`
  - `attack-surface-search.tsx`
  - `node-detail-panel.tsx`
  - `graph-canvas.tsx`
- `Frontend/components/layout/header.tsx` (added navbar link)
- `Frontend/lib/api.ts` (added types + attackSurfaceScan function)
- `Frontend/package.json` (added @xyflow/react, dagre)

## Troubleshooting

**Graph not rendering?**
- Check browser console (F12) for errors
- Ensure `@xyflow/react` CSS is loaded
- Verify the backend endpoint returns valid JSON

**No subdomains found?**
- SecurityTrails free quota may be exhausted
- Try a different domain or wait for quota reset

**Neo4j write fails?**
- This is expected if no credentials are set
- Check `Backend/.env` for NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
- Feature still works without Neo4j (graceful fallback)

## Next Steps (Optional Enhancements)

- [ ] Add subdomain filtering/sorting in side panel
- [ ] Export graph as JSON/CSV
- [ ] Historical attack surface trends
- [ ] Scheduled periodic scans
- [ ] Alert on new subdomains
