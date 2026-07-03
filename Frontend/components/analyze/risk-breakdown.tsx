"use client";

import { AlertTriangle, CheckCircle2, Shield, Info, Zap, Server, FileText, Wifi } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";

export interface RiskBreakdownData {
  domain_name?:    { score: number; max: number; factors: string[] };
  registration?:   { score: number; max: number; factors: string[] };
  infrastructure?: { score: number; max: number; factors: string[] };
  dns_analysis?:   { score: number; max: number; factors: string[] };
  total?: number;
  entropy?: number;
  phishing?: { brand: string; similarity: number; distance: number };
  override?: string;
}

export interface ThreatIntelData {
  threat_level?: string;
  listed_on_feeds?: number;
  feeds?: {
    urlhaus?: {
      listed: boolean | null;
      urls_count?: number;
      active_urls?: number;
      tags?: string[];
      source?: string;
      error?: string;
    };
  };
}

interface Props {
  breakdown: RiskBreakdownData | null | undefined;
  threatIntel: ThreatIntelData | null | undefined;
  domain: string;
}

const categoryMeta = [
  {
    key: "domain_name" as const,
    label: "Domain Name Analysis",
    icon: FileText,
    description: "Entropy, brand impersonation, phishing keywords, TLD risk",
    color: "text-violet-500",
    bg: "bg-violet-500",
  },
  {
    key: "registration" as const,
    label: "Registration Intelligence",
    icon: Shield,
    description: "Domain age, WHOIS privacy, registrar legitimacy",
    color: "text-blue-500",
    bg: "bg-blue-500",
  },
  {
    key: "infrastructure" as const,
    label: "Infrastructure Profiling",
    icon: Server,
    description: "Hosting region, bulletproof ASNs, Shodan exposure",
    color: "text-orange-500",
    bg: "bg-orange-500",
  },
  {
    key: "dns_analysis" as const,
    label: "DNS Pattern Analysis",
    icon: Wifi,
    description: "Fast-flux detection, DNS record anomalies",
    color: "text-cyan-500",
    bg: "bg-cyan-500",
  },
];

function scoreColor(score: number, max: number): string {
  const pct = (score / max) * 100;
  if (pct >= 70) return "bg-red-500";
  if (pct >= 40) return "bg-orange-500";
  if (pct >= 20) return "bg-yellow-500";
  return "bg-green-500";
}

function FactorList({ factors }: { factors: string[] }) {
  if (!factors || factors.length === 0) {
    return (
      <div className="flex items-center gap-2 text-xs text-green-600 dark:text-green-400 mt-2">
        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
        <span>No risk factors detected</span>
      </div>
    );
  }
  return (
    <ul className="mt-2 space-y-1">
      {factors.map((f, i) => (
        <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-500 mt-0.5" />
          <span>{f}</span>
        </li>
      ))}
    </ul>
  );
}

function PhishingAlert({ phishing }: { phishing: RiskBreakdownData["phishing"] }) {
  if (!phishing) return null;
  return (
    <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 mb-4">
      <div className="flex items-center gap-2 mb-1">
        <AlertTriangle className="h-4 w-4 text-red-500" />
        <span className="text-sm font-semibold text-red-500">BrandShield Alert — Phishing Detected</span>
      </div>
      <p className="text-xs text-muted-foreground">
        This domain closely resembles{" "}
        <span className="font-mono font-semibold text-foreground">{phishing.brand}.com</span>{" "}
        with{" "}
        <span className="font-semibold text-red-400">{phishing.similarity}% similarity</span>{" "}
        (edit distance: {phishing.distance}). This is a strong indicator of a phishing or brand
        impersonation attack. Do not enter credentials.
      </p>
    </div>
  );
}

function ThreatIntelSection({ intel }: { intel: ThreatIntelData | null | undefined }) {
  if (!intel) return null;
  const urlhaus = intel.feeds?.urlhaus;
  const level   = intel.threat_level;

  const levelBadge =
    level === "malicious" ? (
      <Badge variant="destructive" className="text-xs">MALICIOUS</Badge>
    ) : level === "clean" ? (
      <Badge className="text-xs bg-green-500/20 text-green-400 border-green-500/30">CLEAN</Badge>
    ) : (
      <Badge variant="secondary" className="text-xs">UNKNOWN</Badge>
    );

  return (
    <div className="mt-4 rounded-lg border border-border p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold">IntelFeed™ Threat Status</span>
        </div>
        {levelBadge}
      </div>
      <div className="grid grid-cols-1 gap-2">
        {urlhaus && (
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">URLhaus (abuse.ch)</span>
            <div className="flex items-center gap-2">
              {urlhaus.listed === true ? (
                <>
                  <span className="text-red-400 font-semibold">LISTED</span>
                  {urlhaus.active_urls !== undefined && (
                    <Badge variant="destructive" className="text-[10px] px-1">
                      {urlhaus.active_urls} active URL{urlhaus.active_urls !== 1 ? "s" : ""}
                    </Badge>
                  )}
                  {urlhaus.tags && urlhaus.tags.length > 0 && (
                    <span className="text-muted-foreground">({urlhaus.tags.slice(0, 3).join(", ")})</span>
                  )}
                </>
              ) : urlhaus.listed === false ? (
                <span className="text-green-400 font-semibold">NOT LISTED</span>
              ) : (
                <span className="text-muted-foreground">
                  {urlhaus.error || "Unavailable"}
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function RiskBreakdown({ breakdown, threatIntel, domain }: Props) {
  if (!breakdown) {
    return (
      <div className="text-sm text-muted-foreground text-center py-8">
        Risk breakdown not available for this scan.
      </div>
    );
  }

  const total   = breakdown.total ?? 0;
  const entropy = breakdown.entropy;

  return (
    <div className="space-y-4">
      {/* Phishing alert banner */}
      <PhishingAlert phishing={breakdown.phishing} />

      {/* Override message (trusted domain) */}
      {breakdown.override && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-3 flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 text-green-500 shrink-0" />
          <span className="text-xs text-green-600 dark:text-green-400">{breakdown.override}</span>
        </div>
      )}

      {/* Overall score bar */}
      <div className="rounded-lg border border-border p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-semibold">ThreatVector™ Score</span>
          <span className={`text-2xl font-bold ${
            total >= 70 ? "text-red-500" :
            total >= 40 ? "text-orange-500" :
            total >= 20 ? "text-yellow-500" : "text-green-500"
          }`}>{total}<span className="text-sm text-muted-foreground font-normal">/100</span></span>
        </div>
        <Progress value={total} className="h-2.5" />
        {entropy !== undefined && entropy > 0 && (
          <p className="text-[11px] text-muted-foreground mt-2">
            Shannon entropy: <span className="font-mono">{entropy.toFixed(2)} bits</span>
            {entropy > 3.5 ? " — elevated (possible DGA)" : " — normal"}
          </p>
        )}
      </div>

      {/* Per-category breakdown */}
      <div className="space-y-3">
        {categoryMeta.map(({ key, label, icon: Icon, description, color, bg }) => {
          const cat = breakdown[key];
          if (!cat) return null;
          const pct = Math.round((cat.score / cat.max) * 100);
          return (
            <div key={key} className="rounded-lg border border-border p-4">
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Icon className={`h-4 w-4 shrink-0 ${color}`} />
                  <div>
                    <p className="text-xs font-semibold">{label}</p>
                    <p className="text-[10px] text-muted-foreground">{description}</p>
                  </div>
                </div>
                <div className="text-right shrink-0 ml-4">
                  <span className={`text-sm font-bold ${
                    pct >= 70 ? "text-red-500" :
                    pct >= 40 ? "text-orange-500" :
                    pct >= 20 ? "text-yellow-500" : "text-green-500"
                  }`}>{cat.score}</span>
                  <span className="text-[10px] text-muted-foreground">/{cat.max}</span>
                </div>
              </div>
              <div className="w-full bg-secondary rounded-full h-1.5 mb-2">
                <div
                  className={`h-1.5 rounded-full transition-all ${scoreColor(cat.score, cat.max)}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <FactorList factors={cat.factors} />
            </div>
          );
        })}
      </div>

      {/* Threat intel */}
      <ThreatIntelSection intel={threatIntel} />

      <p className="text-[10px] text-muted-foreground text-center pt-1">
        Powered by ThreatVector Engine™ + IntelFeed™ · TraceHost v2.0
      </p>
    </div>
  );
}
