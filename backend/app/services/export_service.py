"""
Report Export Service
Converts Advisory Lens report documents into Markdown, STIX 2.1 JSON, and CSV format.
"""
import json
import csv
import io
from datetime import datetime


class ReportExportService:
    async def to_markdown(self, report_doc: dict) -> str:
        """Convert report document to Markdown."""
        report = report_doc.get("report", {})
        actor = report.get("threat_actor", {})
        campaign = report.get("campaign", {})

        md = []
        md.append(f"# {actor.get('name') or 'Cyber Threat Intelligence Report'}")
        md.append(f"**Job ID**: `{report_doc.get('job_id')}` | **TLP**: {report_doc.get('tlp_level', 'WHITE').upper()} | **Date**: {datetime.utcnow().strftime('%Y-%m-%d')}\n")

        if report.get("executive_summary"):
            md.append("## Executive Summary")
            md.append(f"{report['executive_summary']}\n")

        if report.get("technical_overview"):
            md.append("## Technical Overview")
            md.append(f"{report['technical_overview']}\n")

        if actor.get("name"):
            md.append("## Threat Actor Profile")
            md.append(f"- **Name**: {actor.get('name')}")
            if actor.get("aliases"):
                md.append(f"- **Aliases**: {', '.join(actor['aliases'])}")
            if actor.get("origin"):
                md.append(f"- **Origin**: {actor.get('origin')}")
            if actor.get("motivation"):
                md.append(f"- **Motivation**: {actor.get('motivation')}")
            if actor.get("description"):
                md.append(f"\n{actor['description']}\n")

        # MITRE ATT&CK
        techniques = report.get("mitre_techniques", [])
        if techniques:
            md.append("## MITRE ATT&CK Mapping")
            md.append("| Technique ID | Name | Tactic | Confidence |")
            md.append("|--------------|------|--------|------------|")
            for t in techniques:
                md.append(f"| {t.get('technique_id')} | {t.get('technique_name')} | {t.get('tactic')} | {int((t.get('confidence', 0))*100)}% |")
            md.append("")

        # Indicators of Compromise
        iocs = report.get("iocs", {})
        if any(iocs.values()):
            md.append("## Indicators of Compromise (IOCs)")
            for ioc_type, vals in iocs.items():
                if vals:
                    md.append(f"### {ioc_type.upper()}")
                    for v in vals:
                        md.append(f"- `{v}`")
                    md.append("")

        # Detection
        detection = report.get("detection", {})
        if detection:
            md.append("## Detection Guidance")
            if detection.get("detection_notes"):
                md.append(detection["detection_notes"])
            if detection.get("yara_rules"):
                md.append("\n### YARA Rules\n```yara")
                for r in detection["yara_rules"]:
                    md.append(r)
                md.append("```")

        return "\n".join(md)

    async def iocs_to_csv(self, report_doc: dict) -> str:
        """Export all IOCs in a report to CSV."""
        report = report_doc.get("report", {})
        iocs = report.get("iocs", {})

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["type", "value", "report_job_id", "tlp_level"])

        job_id = report_doc.get("job_id", "")
        tlp = report_doc.get("tlp_level", "WHITE")

        for ioc_type, values in iocs.items():
            for val in values:
                writer.writerow([ioc_type, val, job_id, tlp])

        return output.getvalue()

    async def to_stix(self, report_doc: dict) -> dict:
        """Export report as a minimal STIX 2.1 Bundle."""
        report = report_doc.get("report", {})
        job_id = report_doc.get("job_id", "")
        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        stix_objects = []

        # Report Object
        stix_report = {
            "type": "report",
            "spec_version": "2.1",
            "id": f"report--{job_id}",
            "created": now_iso,
            "modified": now_iso,
            "name": "ClarityTI Threat Intelligence Report",
            "description": report.get("executive_summary", ""),
            "published": now_iso,
            "object_refs": [],
        }

        # Threat Actor Object
        actor = report.get("threat_actor", {})
        if actor.get("name"):
            actor_id = f"threat-actor--{job_id[:8]}-1"
            stix_objects.append({
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": now_iso,
                "modified": now_iso,
                "name": actor["name"],
                "aliases": actor.get("aliases", []),
                "description": actor.get("description", ""),
            })
            stix_report["object_refs"].append(actor_id)

        # IOC Indicators
        iocs = report.get("iocs", {})
        idx = 1
        for ioc_type, values in iocs.items():
            for val in values:
                ind_id = f"indicator--{job_id[:8]}-{idx}"
                stix_objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"{ioc_type.upper()}: {val}",
                    "pattern": f"[{ioc_type}:value = '{val}']",
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                })
                stix_report["object_refs"].append(ind_id)
                idx += 1

        stix_objects.append(stix_report)

        return {
            "type": "bundle",
            "id": f"bundle--{job_id}",
            "objects": stix_objects,
        }
