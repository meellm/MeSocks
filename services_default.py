"""
MeSocks — Default Service Configuration (Discord)

This file provides the built-in Discord service definition.
To customize services, copy services_config.example.py to services_config.py
and edit it. The DNS proxy will prefer services_config.py if it exists.
"""

SERVICES = {
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
                r"^[a-z0-9\-]+\d+[a-z0-9\-]*\.discord\.gg$",
                r"^[a-z0-9\-]+\d+[a-z0-9\-]*\.discord\.media$",
            ],
        },
    },
}
