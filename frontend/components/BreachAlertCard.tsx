"use client";

import React from "react";

export interface BreachCardProps {
  banner?: string; // e.g. "⚠️ Breach claim reported" | "🚨 Verified breach reported" | "🛡️ Breach claim denied"
  source?: string; // e.g. "The Hacker News, Reuters, CRN Asia"
  companyName: string; // e.g. "HCL Technologies"
  summary: string;
  dateReported?: string; // e.g. "Aug 11, 2026" or "Not disclosed"
  country?: string; // e.g. "🇮🇳 India" or "Unknown"
  threatActor?: string; // e.g. "TheHatman" or "Unattributed"
  claimedRecords?: string; // e.g. "250,000+" or "Not disclosed"
  claimedVector?: string; // e.g. "Compromised Azure credentials" or "Not disclosed"
  companyResponse?: string; // e.g. "No systems breached" | "Breach confirmed" | "Under investigation" | "No statement yet"
  badgeText?: string; // e.g. "Unverified claim" | "Verified breach" | "Claim denied"
  sourceUrl?: string;
  isFallback?: boolean;
}

export const BreachAlertCard: React.FC<BreachCardProps> = ({
  banner = "⚠️ Breach claim reported",
  source = "[outlet names]",
  companyName = "[Company name]",
  summary,
  dateReported = "Not disclosed",
  country = "Unknown",
  threatActor = "Unattributed",
  claimedRecords = "Not disclosed",
  claimedVector = "Not disclosed",
  companyResponse = "No statement yet",
  badgeText = "Unverified claim",
  sourceUrl = "#",
  isFallback = false,
}) => {
  // Response status color styling
  let responseClass = "text-[#7a7a80]";
  if (companyResponse === "No systems breached") responseClass = "text-[#97c459] font-medium";
  else if (companyResponse === "Breach confirmed") responseClass = "text-[#f09595] font-medium";
  else if (companyResponse === "Under investigation") responseClass = "text-[#fac775] font-medium";

  return (
    <div className="w-full max-w-[460px] rounded-xl border border-[#5a2323] bg-[#202024] overflow-hidden text-sm shadow-xl font-sans">
      {/* Header Banner */}
      <div className="bg-[#3a1414] px-4 py-3 flex items-center gap-2 border-b border-[#4a1818]">
        <span className="text-[#f09595] font-medium text-sm">{banner}</span>
      </div>

      {/* Body */}
      <div className="p-5">
        <p className="text-xs text-[#8a8a8f] mb-1">
          Source · {source || "[outlet names]"}
        </p>

        <h3 className="text-lg font-medium text-[#f2f2f2] mb-2.5">
          {companyName}
        </h3>

        <p className="text-xs leading-relaxed text-[#b5b5ba] mb-3.5">
          {summary || "[One or two sentence plain-language summary: what was claimed, by whom, and what the company has said in response.]"}
        </p>

        {/* Fact Table */}
        <table className="w-full text-xs border-collapse my-2">
          <tbody>
            <tr className="border-b border-[#2b2b30]/40">
              <td className="py-1.5 text-[#b5b5ba] w-[40%]">Date reported</td>
              <td className={`py-1.5 text-right ${dateReported === "Not disclosed" ? "text-[#7a7a80]" : "text-[#f2f2f2] font-medium"}`}>
                {dateReported}
              </td>
            </tr>
            <tr className="border-b border-[#2b2b30]/40">
              <td className="py-1.5 text-[#b5b5ba]">Country</td>
              <td className={`py-1.5 text-right ${country === "Unknown" ? "text-[#7a7a80]" : "text-[#f2f2f2] font-medium"}`}>
                {country}
              </td>
            </tr>
            <tr className="border-b border-[#2b2b30]/40">
              <td className="py-1.5 text-[#b5b5ba]">Threat actor</td>
              <td className={`py-1.5 text-right ${threatActor === "Unattributed" ? "text-[#7a7a80]" : "text-[#f2f2f2] font-medium"}`}>
                {threatActor}
              </td>
            </tr>
            <tr className="border-b border-[#2b2b30]/40">
              <td className="py-1.5 text-[#b5b5ba]">Claimed records</td>
              <td className={`py-1.5 text-right ${claimedRecords === "Not disclosed" ? "text-[#7a7a80]" : "text-[#f2f2f2] font-medium"}`}>
                {claimedRecords}
              </td>
            </tr>
            <tr className="border-b border-[#2b2b30]/40">
              <td className="py-1.5 text-[#b5b5ba]">Claimed vector</td>
              <td className={`py-1.5 text-right ${claimedVector === "Not disclosed" ? "text-[#7a7a80]" : "text-[#f2f2f2] font-medium"}`}>
                {claimedVector}
              </td>
            </tr>
            <tr>
              <td className="py-1.5 text-[#b5b5ba]">Company response</td>
              <td className={`py-1.5 text-right ${responseClass}`}>
                {companyResponse}
              </td>
            </tr>
          </tbody>
        </table>

        {/* Footer */}
        <div className="mt-3 pt-2.5 border-t border-[#3a3a3f] flex items-center justify-between">
          <span className="text-[11px] bg-[#412402] text-[#fac775] px-2.5 py-0.5 rounded-md font-medium">
            {badgeText}
          </span>
          <a
            href={sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-[#378add] hover:underline flex items-center gap-1"
          >
            Read source ↗
          </a>
        </div>
      </div>
    </div>
  );
};
