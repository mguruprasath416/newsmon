"""
ClarityTI — Threat Actor Entity Matching & Article Linking Service
Scans articles for Threat Actor primary names, aliases, APT designations,
and nation-state campaigns. Updates article threat_actors field and syncs stats.
"""

import re
import structlog
from typing import List, Dict, Any, Set, Optional
from datetime import datetime, timezone
from app.db.mongodb import get_articles_collection, get_threat_actors_collection

log = structlog.get_logger()

# ── Comprehensive Threat Actor & APT Taxonomy (150+ Groups & Aliases) ─────────
BUILTIN_ACTOR_TAXONOMY = {
    # ── Russian Nation-State & Intelligence APTs ──
    "Fancy Bear (APT28)": ["fancy bear", "apt28", "apt-28", "strontium", "forest blizzard", "pawn storm", "sofacy", "sednit", "gru unit 26165"],
    "Cozy Bear (APT29)": ["cozy bear", "apt29", "apt-29", "nobelium", "midnight blizzard", "the dukes", "svr", "office monkeys", "unc2452"],
    "Sandworm": ["sandworm", "voodoo bear", "seashell blizzard", "electrum", "telebots", "gru unit 74455", "blackenergy group", "iron viking"],
    "Turla": ["turla", "waterbug", "snake", "venomous bear", "secret blizzard", "krypton", "belugasturgeon", "fsb turla"],
    "Gamaredon": ["gamaredon", "primitive bear", "armageddon", "shuckworm", "actinium", "calisto"],
    "Callisto Group": ["callisto", "coldriver", "star blizzard", "seaborgium", "ta446", "bluecharlie"],
    "Cadet Blizzard": ["cadet blizzard", "gru unit 29155", "bleeding bear", "unc2589", "ember bear"],
    "FIN7": ["fin7", "carbanak", "elbrus", "sangria tempest"],
    "Evil Corp / TA505": ["evil corp", "ta505", "indrik spider", "dridex group", "hive0065"],
    "Wizard Spider": ["wizard spider", "trickbot group", "gold blackburn", "grim spider"],

    # ── Chinese Nation-State APTs ──
    "Volt Typhoon": ["volt typhoon", "bronze silhouette", "vanguard panda", "storm-0391", "dev-0391"],
    "Salt Typhoon": ["salt typhoon", "famous sparrow", "ghostemperor", "unc2286"],
    "Flax Typhoon": ["flax typhoon", "storm-0940"],
    "Silk Typhoon": ["silk typhoon", "hafnium"],
    "APT41": ["apt41", "apt-41", "double dragon", "barium", "wicked panda", "winnti", "brass typhoon", "red kelpie"],
    "APT10": ["apt10", "apt-10", "stone panda", "red apollo", "potassium", "menuPass"],
    "APT27": ["apt27", "apt-27", "emissary panda", "luckymouse", "bronze union", "iron tiger"],
    "APT31": ["apt31", "apt-31", "judgment panda", "zirconium", "red kestrel"],
    "APT20": ["apt20", "apt-20", "twilled panda"],
    "APT15": ["apt15", "apt-15", "vixen panda", "ke3chang", "playful dragon"],
    "Mustang Panda": ["mustang panda", "bronze president", "camaro dragon", "ta428", "reddelta", "stately taurus"],
    "UNC3886": ["unc3886", "unc-3886"],
    "Earth Baxia": ["earth baxia"],
    "Earth Lusca": ["earth lusca", "aquatic panda"],
    "Earth Krahang": ["earth krahang"],

    # ── Iranian Nation-State APTs ──
    "Charming Kitten (APT35)": ["charming kitten", "apt35", "apt-35", "mint sandstorm", "phosphorus", "newsbeef", "newscaster", "ajax security", "ta453"],
    "APT42": ["apt42", "apt-42", "yellow garuda", "nicophorite", "calamity kitten", "unc788"],
    "MuddyWater": ["muddywater", "static kitten", "mango sandstorm", "mercury", "seedworm", "earth vetala", "ta450"],
    "OilRig (APT34)": ["oilrig", "apt34", "apt-34", "helix kitten", "cobalt gypsy", "europium", "hazel sandstorm", "crambus"],
    "Cotton Sandstorm": ["cotton sandstorm", "emennet pasargad", "marbled dust", "neptunium"],
    "Peach Sandstorm": ["peach sandstorm", "holmium"],
    "Pioneer Kitten": ["pioneer kitten", "fox kitten", "unc757", "parisite", "lemon sandstorm", "rubidium"],
    "CyberAv3ngers": ["cyberav3ngers", "cyber av3ngers", "cyberavengers"],
    "Handala": ["handala", "handala hack", "handalahack"],
    "Moses Staff": ["moses staff"],
    "Agrius": ["agrius", "blackshadow", "pink sandstorm"],

    # ── North Korean APTs ──
    "Lazarus Group": ["lazarus", "lazarus group", "hidden cobra", "diamond sleet", "zinc", "apt38", "apt-38", "whois", "labyrinth chollima"],
    "Kimsuky": ["kimsuky", "velvet chollima", "emerald sleet", "thallium", "black banshee"],
    "Andariel": ["andariel", "onyx sleet", "stone chollima", "plutonium", "silent chollima"],
    "ScarCruft (APT37)": ["scarcruft", "apt37", "apt-37", "reaper", "ruby sleet", "ricochet chollima", "group123"],
    "BlueNoroff": ["bluenoroff", "stardust chollima", "sapphire sleet"],

    # ── South Asian / Indian Subcontinent APTs ──
    "SideCopy": ["sidecopy", "side copy"],
    "Transparent Tribe (APT36)": ["transparent tribe", "apt36", "apt-36", "mythic leopard", "copper fieldstone"],
    "Patchwork": ["patchwork", "dropping elephant", "monsoon", "hangover", "chinastrats"],
    "Bitter": ["bitter", "t-apt-17"],
    "Sidewinder": ["sidewinder", "rattlesnake", "razor tiger"],
    "DoNot Team": ["donot team", "apt-c-35", "donot group"],
    "Confucius": ["confucius apt"],

    # ── Major Cybercrime & Ransomware Groups ──
    "LockBit": ["lockbit", "lockbit 2.0", "lockbit 3.0", "lockbit black", "lockbit green"],
    "Scattered Spider": ["scattered spider", "unc3944", "octo tempest", "starfraud", "scatter swine"],
    "RansomHub": ["ransomhub", "ransom hub"],
    "ALPHV / BlackCat": ["alphv", "blackcat", "alphv/blackcat"],
    "Akira": ["akira", "akira ransomware"],
    "BlackBasta": ["blackbasta", "black basta"],
    "Play Ransomware": ["play ransomware", "play crypt", "playcrypt"],
    "Medusa": ["medusa", "medusa ransomware", "medusa blog"],
    "Qilin": ["qilin", "agenda ransomware"],
    "Rhysida": ["rhysida", "rhysida ransomware"],
    "BianLian": ["bianlian", "bian lian"],
    "Clop": ["clop", "cl0p"],
    "Space Bears": ["space bears", "spacebears"],
    "DireWolf": ["direwolf", "dire wolf"],
    "Settra": ["settra", "settra ransomware"],
    "DarkSide / BlackMatter": ["darkside", "blackmatter"],
    "Conti": ["conti ransomware"],
    "Lapsus$": ["lapsus$", "lapsus", "lapsus group"],
    "ShinyHunters": ["shinyhunters", "shiny hunters"],
    "Storm-0501": ["storm-0501"],
    "Storm-0216": ["storm-0216"],
}

# ── Dynamic Generic Designation Patterns ─────────────────────────────────────
GENERIC_APT_REGEX = re.compile(r"\b(APT-?[0-9]{1,3})\b", re.IGNORECASE)
GENERIC_UNC_REGEX = re.compile(r"\b(UNC-?[0-9]{3,5})\b", re.IGNORECASE)
GENERIC_STORM_REGEX = re.compile(r"\b(Storm-[0-9]{4})\b", re.IGNORECASE)
GENERIC_TA_REGEX = re.compile(r"\b(TA[0-9]{3,4})\b", re.IGNORECASE)

# Dynamic state-sponsored generic classifications
STATE_SPONSORED_PATTERNS = [
    (re.compile(r"\b(iranian|iran-linked|irgc)\s+(threat actor|hackers?|cyber group|state-sponsored|cyber offensive)\b", re.I), "Iranian State-Sponsored Actor"),
    (re.compile(r"\b(russian|russia-linked|gru|fsb|svr)\s+(threat actor|hackers?|cyber group|state-sponsored)\b", re.I), "Russian State-Sponsored Actor"),
    (re.compile(r"\b(chinese|china-linked|mss|pla)\s+(threat actor|hackers?|cyber group|state-sponsored)\b", re.I), "Chinese State-Sponsored Actor"),
    (re.compile(r"\b(north korean|dprk|north korea-linked)\s+(threat actor|hackers?|cyber group|state-sponsored)\b", re.I), "North Korean State-Sponsored Actor"),
]


def build_compiled_actor_patterns(db_actors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build compiled regex patterns combining DB actors and built-in taxonomy."""
    patterns_map = {}

    # 1. Add built-in taxonomy
    for primary_name, aliases in BUILTIN_ACTOR_TAXONOMY.items():
        all_names = set([primary_name] + aliases)
        regex_parts = [r"\b" + re.escape(n) + r"\b" for n in all_names if len(n) >= 3]
        if regex_parts:
            patterns_map[primary_name] = {
                "name": primary_name,
                "regex": re.compile("|".join(regex_parts), re.IGNORECASE)
            }

    # 2. Add DB actors
    for actor in db_actors:
        name = actor.get("name")
        if not name:
            continue
        aliases = actor.get("aliases") or []
        all_names = set([name] + aliases)
        regex_parts = [r"\b" + re.escape(n) + r"\b" for n in all_names if len(n) >= 3]
        if regex_parts:
            patterns_map[name] = {
                "id": actor.get("_id"),
                "name": name,
                "regex": re.compile("|".join(regex_parts), re.IGNORECASE)
            }

    return list(patterns_map.values())


def extract_threat_actors_from_text(text: str, compiled_patterns: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    """Extract matching threat actor names from text snippet using taxonomy and dynamic patterns."""
    if not text or len(text.strip()) < 5:
        return []

    if not compiled_patterns:
        compiled_patterns = build_compiled_actor_patterns([])

    found = set()

    # 1. Check taxonomy compiled patterns
    for ap in compiled_patterns:
        if ap["regex"].search(text):
            found.add(ap["name"])

    # 2. Dynamic APT designation extraction (e.g. APT28, APT42, APT35)
    for m in GENERIC_APT_REGEX.findall(text):
        normalized = m.upper().replace("-", "")
        # Avoid overriding canonical names if already captured
        if not any(normalized in f.upper() for f in found):
            found.add(normalized)

    # 3. Dynamic UNC / Storm / TA designation extraction
    for m in GENERIC_UNC_REGEX.findall(text):
        found.add(m.upper().replace("-", ""))
    for m in GENERIC_STORM_REGEX.findall(text):
        found.add(f"Storm-{m.split('-')[-1]}")
    for m in GENERIC_TA_REGEX.findall(text):
        found.add(m.upper())

    # 4. State-sponsored attribution checks
    for pat, label in STATE_SPONSORED_PATTERNS:
        if pat.search(text):
            # Only add general label if no specific named group was identified
            if not found:
                found.add(label)

    # Remove any Unattributed / Unknown strings
    cleaned = [a for a in found if a and a.lower() != "unattributed" and a.lower() != "unknown"]
    return sorted(cleaned)


async def link_all_articles_to_threat_actors() -> dict:
    """
    Match all threat actors against all articles in MongoDB.
    Updates the 'threat_actors' list on articles (clearing 'Unattributed' placeholders)
    and updates article counts on threat actor documents.
    """
    actors_col = get_threat_actors_collection()
    articles_col = get_articles_collection()

    # Fetch DB actors
    actors_cursor = actors_col.find({})
    db_actors = await actors_cursor.to_list(length=2000)

    actor_patterns = build_compiled_actor_patterns(db_actors)

    from pymongo import UpdateOne
    bulk_ops = []

    # Stream articles efficiently using async for
    articles_cursor = articles_col.find({})
    total_articles = 0
    articles_tagged = 0
    actor_counts = {ap["name"]: 0 for ap in actor_patterns}

    async for art in articles_cursor:
        total_articles += 1
        if total_articles % 500 == 0:
            log.info("Threat actor matching in progress...", processed=total_articles, tagged=articles_tagged)

        text_to_check = f"{art.get('title', '')} {art.get('summary', '')} {art.get('content_clean', '')[:10000]}"
        
        # Extract actors using full taxonomy + dynamic regex
        matched_actors = set(extract_threat_actors_from_text(text_to_check, actor_patterns))

        # Also carry forward any valid pre-existing actors
        for a in (art.get("threat_actors") or []):
            if a and str(a).lower() not in ("unattributed", "unknown", "none"):
                matched_actors.add(a)

        for act_name in matched_actors:
            if act_name in actor_counts:
                actor_counts[act_name] += 1

        new_actor_list = sorted(list(matched_actors))
        old_actor_list = sorted(art.get("threat_actors") or [])

        # Update if changed (this will cleanly remove ["Unattributed"] -> [])
        if new_actor_list != old_actor_list:
            articles_tagged += 1
            bulk_ops.append(UpdateOne(
                {"_id": art["_id"]},
                {"$set": {"threat_actors": new_actor_list, "updated_at": datetime.now(timezone.utc)}}
            ))

        if len(bulk_ops) >= 500:
            await articles_col.bulk_write(bulk_ops, ordered=False)
            bulk_ops = []

    if bulk_ops:
        await articles_col.bulk_write(bulk_ops, ordered=False)

    # Update Threat Actor document stats for DB actors
    updated_actors_count = 0
    for ap in actor_patterns:
        cnt = actor_counts.get(ap["name"], 0)
        if "id" in ap and cnt > 0:
            updated_actors_count += 1
            await actors_col.update_one(
                {"_id": ap["id"]},
                {"$set": {"article_count": cnt, "updated_at": datetime.now(timezone.utc)}}
            )

    top_linked = dict(sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:15])

    log.info(
        "Threat actor entity matching finished",
        total_articles=total_articles,
        articles_tagged=articles_tagged,
        threat_actors_updated=updated_actors_count
    )

    return {
        "total_articles": total_articles,
        "articles_tagged": articles_tagged,
        "threat_actors_updated": updated_actors_count,
        "top_linked_actors": top_linked
    }
