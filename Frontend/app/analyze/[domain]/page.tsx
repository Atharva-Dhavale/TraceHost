'use client';

import { DomainResults } from '@/components/analyze/domain-results';

export default function DomainAnalysisPage({
  params,
}: {
  params: { domain: string };
}) {
  const decodedDomain = decodeURIComponent(params.domain);

  if (!decodedDomain) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[calc(100vh-4rem)]">
        <div className="max-w-md text-center space-y-4">
          <h1 className="text-2xl font-bold text-destructive">No Domain Specified</h1>
          <a
            href="/"
            className="inline-block px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            Return to Home
          </a>
        </div>
      </div>
    );
  }

  return <DomainResults domain={decodedDomain} />;
}
