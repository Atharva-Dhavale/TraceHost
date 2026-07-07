"use client";

import dynamic from "next/dynamic";
import { useMemo, useCallback, Suspense } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { AttackSurfaceNode, AttackSurfaceEdge } from "@/lib/api";

const GraphCanvas = dynamic(() => import("./graph-canvas").then(m => ({ default: m.GraphCanvas })), {
  ssr: false,
  loading: () => (
    <div className="h-[70vh] w-full rounded-xl border border-border overflow-hidden bg-card/40 flex items-center justify-center">
      <Skeleton className="h-full w-full" />
    </div>
  ),
});

interface AttackSurfaceGraphProps {
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
  onNodeClick: (node: AttackSurfaceNode) => void;
}

export function AttackSurfaceGraph({ nodes, edges, onNodeClick }: AttackSurfaceGraphProps) {
  return (
    <Suspense fallback={<Skeleton className="h-[70vh] w-full rounded-xl" />}>
      <GraphCanvas nodes={nodes} edges={edges} onNodeClick={onNodeClick} />
    </Suspense>
  );
}
