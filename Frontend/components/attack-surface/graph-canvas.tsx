"use client";

import { useMemo, useCallback, useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "dagre";
import { Globe, Server, Network, Radio, MapPin, ShieldCheck } from "lucide-react";
import type { AttackSurfaceNode, AttackSurfaceEdge, AttackSurfaceNodeType } from "@/lib/api";

const NODE_WIDTH = 190;
const NODE_HEIGHT = 56;

const TYPE_META: Record<
  AttackSurfaceNodeType,
  { icon: typeof Globe; color: string; bg: string }
> = {
  domain:    { icon: Globe,       color: "#a78bfa", bg: "#a78bfa15" },
  subdomain: { icon: Server,      color: "#60a5fa", bg: "#60a5fa15" },
  ip:        { icon: Network,     color: "#f87171", bg: "#f8717115" },
  asn:       { icon: Radio,       color: "#fbbf24", bg: "#fbbf2415" },
  country:   { icon: MapPin,      color: "#34d399", bg: "#34d39915" },
  ssl:       { icon: ShieldCheck, color: "#818cf8", bg: "#818cf815" },
};

function GraphNode({ data }: NodeProps) {
  const nodeType = data.type as AttackSurfaceNodeType;
  const meta = TYPE_META[nodeType];
  const Icon = meta.icon;
  const nodeData = data.data as Record<string, any> | undefined;
  const riskScore = nodeData?.risk_score as number | undefined;

  return (
    <div
      className="rounded-lg border px-3 py-2 flex items-center gap-2 cursor-pointer transition-transform hover:scale-105"
      style={{
        width: NODE_WIDTH,
        borderColor: meta.color,
        backgroundColor: meta.bg,
        borderWidth: "2px"
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: meta.color }} />
      <Icon className="h-4 w-4 shrink-0" style={{ color: meta.color }} />
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium truncate" title={data.label as string}>
          {data.label as string}
        </div>
        {typeof riskScore === "number" && (
          <div className="text-[10px] opacity-70">Risk: {riskScore}</div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: meta.color }} />
    </div>
  );
}

const nodeTypes = {
  graphNode: GraphNode,
};

function layoutGraph(nodes: AttackSurfaceNode[], edges: AttackSurfaceEdge[]) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", nodesep: 40, ranksep: 90 });

  nodes.forEach((n) => g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  edges.forEach((e) => g.setEdge(e.source, e.target));

  dagre.layout(g);

  const flowNodes: Node[] = nodes.map((n) => {
    const pos = g.node(n.id);
    return {
      id: n.id,
      type: "graphNode",
      position: { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 },
      data: { label: n.label, type: n.type, data: n.data },
    };
  });

  const flowEdges: Edge[] = edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.relationship,
    animated: true,
  }));

  return { flowNodes, flowEdges };
}

interface GraphCanvasProps {
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
  onNodeClick: (node: AttackSurfaceNode) => void;
}

export function GraphCanvas({ nodes, edges, onNodeClick }: GraphCanvasProps) {
  const { flowNodes, flowEdges } = useMemo(() => layoutGraph(nodes, edges), [nodes, edges]);
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState(flowNodes);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState(flowEdges);

  useEffect(() => {
    setRfNodes(flowNodes);
    setRfEdges(flowEdges);
  }, [flowNodes, flowEdges, setRfNodes, setRfEdges]);

  const nodesById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const original = nodesById.get(node.id);
      if (original) onNodeClick(original);
    },
    [nodesById, onNodeClick]
  );

  return (
    <div style={{ width: "100%", height: "70vh" }} className="rounded-xl border border-border overflow-hidden bg-card/40">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={nodeTypes}
        fitView
      >
        <Background gap={16} />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  );
}
