"use client";

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import type { AttackSurfaceNode, AttackSurfaceEdge } from "@/lib/api";

interface NodeDetailPanelProps {
  node: AttackSurfaceNode | null;
  edges: AttackSurfaceEdge[];
  nodesById: Map<string, AttackSurfaceNode>;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const TYPE_LABEL: Record<string, string> = {
  domain: "Domain",
  subdomain: "Subdomain",
  ip: "IP Address",
  asn: "ASN",
  country: "Country",
  ssl: "SSL Certificate",
};

function riskLabel(score: number) {
  if (score >= 70) return { label: "High", className: "bg-destructive/15 text-destructive" };
  if (score >= 40) return { label: "Medium", className: "bg-yellow-500/15 text-yellow-500" };
  return { label: "Low", className: "bg-emerald-500/15 text-emerald-500" };
}

export function NodeDetailPanel({ node, edges, nodesById, open, onOpenChange }: NodeDetailPanelProps) {
  if (!node) return null;

  const connected = edges
    .filter((e) => e.source === node.id || e.target === node.id)
    .map((e) => {
      const otherId = e.source === node.id ? e.target : e.source;
      return { relationship: e.relationship, node: nodesById.get(otherId) };
    })
    .filter((c) => c.node);

  const riskScore = node.data?.risk_score as number | undefined;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="glass-card border-0 overflow-y-auto">
        <SheetHeader className="mb-4">
          <SheetTitle className="break-all">{node.label}</SheetTitle>
          <SheetDescription>{TYPE_LABEL[node.type] || node.type}</SheetDescription>
        </SheetHeader>

        <div className="space-y-4">
          {typeof riskScore === "number" && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Risk Score</span>
              <Badge className={riskLabel(riskScore).className}>
                {riskScore} · {riskLabel(riskScore).label}
              </Badge>
            </div>
          )}

          <div className="space-y-1">
            {Object.entries(node.data || {})
              .filter(([key]) => key !== "risk_score")
              .map(([key, value]) => (
                <div key={key} className="flex justify-between text-sm border-b border-border/50 py-1.5">
                  <span className="text-muted-foreground capitalize">{key.replace(/_/g, " ")}</span>
                  <span className="text-right break-all max-w-[60%]">
                    {value === null || value === undefined || value === "" ? "—" : String(value)}
                  </span>
                </div>
              ))}
          </div>

          {connected.length > 0 && (
            <div>
              <h4 className="text-sm font-medium mb-2">
                Connected Nodes ({connected.length})
              </h4>
              <div className="space-y-1.5">
                {connected.map(({ relationship, node: n }, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between text-sm rounded-md bg-accent/5 px-2 py-1.5"
                  >
                    <span className="truncate">{n!.label}</span>
                    <Badge variant="outline" className="text-[10px] shrink-0 ml-2">
                      {relationship.replace(/_/g, " ")}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
