import logging

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .services import graph_builder

logger = logging.getLogger(__name__)

ATTACK_SURFACE_CACHE_TTL = getattr(settings, "ATTACK_SURFACE_CACHE_TTL", 43200)


def _cache_key(domain: str) -> str:
    return f"attack_surface:{domain.lower()}"


@csrf_exempt
def attack_surface_scan(request):
    domain = request.GET.get("domain", "").strip()
    if not domain:
        return JsonResponse({"error": "No domain provided"}, status=400)

    if not graph_builder.is_valid_domain(domain):
        return JsonResponse({"error": "Invalid domain"}, status=400)

    cache_key = _cache_key(domain)
    cached = cache.get(cache_key)
    if cached is not None:
        logger.info("Attack surface cache hit for %s", domain)
        return JsonResponse({**cached, "cached": True})

    try:
        result = graph_builder.build_graph(domain)
        if result.get("error"):
            return JsonResponse(result, status=400)
        cache.set(cache_key, result, ATTACK_SURFACE_CACHE_TTL)
        return JsonResponse({**result, "cached": False})
    except Exception as exc:
        logger.error("attack_surface_scan failed for %s: %s", domain, exc)
        return JsonResponse({"error": "Scan failed", "message": str(exc)}, status=500)


@csrf_exempt
def invalidate_attack_surface_cache(request):
    domain = request.GET.get("domain", "").strip()
    if not domain:
        return JsonResponse({"error": "No domain provided"}, status=400)

    cache.delete(_cache_key(domain))
    logger.info("Attack surface cache invalidated for %s", domain)
    return JsonResponse({"domain": domain, "cache_cleared": True})
