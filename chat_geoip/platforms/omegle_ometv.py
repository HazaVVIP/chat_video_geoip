"""Platform profiles for Omegle / OmeTV."""

from __future__ import annotations

PLATFORM_PROFILES: dict[str, dict] = {
    "ometv": {
        "url": "https://ome.tv",
        "filter_preset": "omegle-ometv",
        "sni_keywords": ("ome.tv", "ometv"),
    },
    "omegle": {
        "url": "https://www.omegle.com",
        "filter_preset": "omegle-ometv",
        "sni_keywords": ("omegle",),
    },
}


def get_platform_url(platform: str, override_url: str = "") -> str:
    if override_url:
        return override_url
    profile = PLATFORM_PROFILES.get(platform.lower(), {})
    return profile.get("url", "https://ome.tv")


def get_platform_filter_preset(platform: str) -> str:
    profile = PLATFORM_PROFILES.get(platform.lower(), {})
    return profile.get("filter_preset", "omegle-ometv")


def apply_platform_config(platform: str, cfg) -> None:
    """Mutate RunConfig with platform defaults."""
    if not platform:
        return
    preset = get_platform_filter_preset(platform)
    if cfg.filter_preset == "video-chat":
        cfg.filter_preset = preset
    cfg.platform = platform.lower()
