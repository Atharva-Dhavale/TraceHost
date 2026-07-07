"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { AttackSurfaceSearch } from "@/components/attack-surface/attack-surface-search";
import { AttackSurfaceGraph } from "@/components/attack-surface/attack-surface-graph";
import { NodeDetailPanel } from "@/components/attack-surface/node-detail-panel";
import { attackSurfaceScan, type AttackSurfaceGraphResponse, type AttackSurfaceNode } from "@/lib/api";

export default function AttackSurfacePage() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams.get("domain") || "";

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [graph, setGraph] = useState<AttackSurfaceGraphResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackSurfaceNode | null>(null);
  const [panelOpen, setPanelOpen] = useState(false);

  const nodesById = useMemo(
    () => new Map((graph?.nodes || []).map((n) => [n.id, n])),
    [graph]
  );

  const handleScan = useCallback(async (domain: string) => {
    setIsLoading(true);
    setError(null);
    setGraph(null);
    try {
      const result = await attackSurfaceScan(domain);
      if (result.error) {
        setError(result.error);
      } else {
        setGraph(result);
      }
    } catch (err: any) {
      setError(
        err?.response?.data?.message || err?.message || "Failed to scan attack surface"
      );
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleNodeClick = (node: AttackSurfaceNode) => {
    setSelectedNode(node);
    setPanelOpen(true);
  };

  useEffect(() => {
    if (!initialDomain) return;
    handleScan(initialDomain);
  }, [initialDomain, handleScan]);

  return (
    <div className="flex min-h-screen flex-col">
      <main className="flex-1 p-6 pt-16 md:pt-20 analyze-page-content">
        <div className="container mx-auto py-6">
          <div className="flex flex-col space-y-6 max-w-6xl mx-auto">
            <AttackSurfaceSearch onScan={handleScan} isLoading={isLoading} initialDomain={initialDomain} />

            {isLoading && (
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <Skeleton className="h-4 w-48" />
                  <Skeleton className="h-[60vh] w-full rounded-xl" />
                </CardContent>
              </Card>
            )}

            {!isLoading && error && (
              <Card className="border-destructive/40">
                <CardContent className="pt-6">
                  <p className="text-destructive text-sm">{error}</p>
                </CardContent>
              </Card>
            )}

            {!isLoading && !error && graph && graph.nodes.length > 0 && (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline">{graph.domain}</Badge>
                  <Badge variant="outline">{graph.subdomain_count} subdomains</Badge>
                  <Badge variant="outline">{graph.cached ? "Cached result" : "Fresh scan"}</Badge>
                  <Badge variant="outline">
                    {graph.neo4j_persisted ? "Persisted to Neo4j" : "Neo4j unavailable"}
                  </Badge>
                </div>
                <AttackSurfaceGraph
                  nodes={graph.nodes}
                  edges={graph.edges}
                  onNodeClick={handleNodeClick}
                />
              </div>
            )}

            {!isLoading && !error && graph && graph.nodes.length === 0 && (
              <Card>
                <CardContent className="pt-6">
                  <p className="text-muted-foreground text-sm">
                    No subdomains found for this domain.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </main>

      <NodeDetailPanel
        node={selectedNode}
        edges={graph?.edges || []}
        nodesById={nodesById}
        open={panelOpen}
        onOpenChange={setPanelOpen}
      />
    </div>
  );
}
