"""
MeSocks — Service Configuration

Copy this file to services_config.py and edit it to customize which
services are routed through VPN.

Each service needs:
  - "domains": list of base domains (subdomains are matched automatically)
  - "udp_proxy" (optional): for services that need UDP forwarding (e.g., Discord voice)

To add a new service, just add a new entry to the SERVICES dict below.
To remove a service, delete or comment out its entry.
"""

SERVICES = {
    # ── Discord (voice + text + CDN) ──────────────────────────
    "discord": {
        "domains": [
            "discord.com",
            "discord.gg",
            "discord.media",
            "discord.gift",
            "discord.gifts",
            "discord.new",
            "discord.dev",
            "discord.co",
            "discord.store",
            "discord.tools",
            "discord.design",
            "discord.app",
            "discordapp.com",
            "discordapp.net",
            "discordapp.io",
            "discordcdn.com",
            "discordstatus.com",
            "discordmerch.com",
            "discordactivities.com",
            "discord-activities.com",
            "discordpartygames.com",
            "discordsays.com",
            "discordsez.com",
            "discordquests.com",
            "discordstatic.com",
            "dis.gd",
        ],
        "udp_proxy": {
            "enabled": True,
            "port": 443,
            "media_patterns": [
                r"^[a-z\-]+\d+\.discord\.gg$",
                r"^[a-z\-]+\d+\.discord\.media$",
            ],
        },
    },

    # ── Spotify (uncomment to enable) ─────────────────────────
    # "spotify": {
    #     "domains": [
    #         "spotify.com",
    #         "scdn.co",
    #         "spotifycdn.com",
    #         "spotify.design",
    #         "spotilocal.com",
    #         "audio-sp-tyo.pscdn.co",
    #     ],
    # },

    # ── Netflix (uncomment to enable) ─────────────────────────
    # "netflix": {
    #     "domains": [
    #         "netflix.com",
    #         "netflix.net",
    #         "nflxvideo.net",
    #         "nflximg.net",
    #         "nflxext.com",
    #         "nflxso.net",
    #     ],
    # },

    # ── YouTube (uncomment to enable) ─────────────────────────
    # "youtube": {
    #     "domains": [
    #         "youtube.com",
    #         "googlevideo.com",
    #         "ytimg.com",
    #         "youtu.be",
    #         "youtube-nocookie.com",
    #         "youtube-ui.l.google.com",
    #     ],
    # },
}
