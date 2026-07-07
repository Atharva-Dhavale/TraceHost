"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Search } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface AttackSurfaceSearchProps {
  onScan: (domain: string) => void;
  isLoading: boolean;
  initialDomain?: string;
}

export function AttackSurfaceSearch({ onScan, isLoading, initialDomain = "" }: AttackSurfaceSearchProps) {
  const [domain, setDomain] = useState(initialDomain);
  const { toast } = useToast();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = domain.trim();
    if (!trimmed) {
      toast({
        title: "Error",
        description: "Please enter a root domain",
        variant: "destructive",
      });
      return;
    }
    onScan(trimmed);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attack Surface Explorer</CardTitle>
        <CardDescription>
          Enter a root domain to map its subdomains, IPs, ASNs, countries, and SSL certificates as an interactive graph
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="flex w-full items-center space-x-2">
          <Input
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="flex-1"
            disabled={isLoading}
          />
          <Button type="submit" disabled={isLoading}>
            {isLoading ? (
              <>
                <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
                Scanning...
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                Scan
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
