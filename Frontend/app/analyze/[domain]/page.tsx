'use client';

import { DomainResults } from '@/components/analyze/domain-results';

export default function DomainAnalysisPage({
  params,
}: {
  params: { domain: string };
}) {
  // Decode the domain from the URL
  const decodedDomain = decodeURIComponent(params.domain);

  return <DomainResults domain={decodedDomain} />;
} 
