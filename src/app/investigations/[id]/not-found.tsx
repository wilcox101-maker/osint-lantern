import Link from "next/link";

import { SiteFrame } from "@/components/site-frame";

export default function InvestigationNotFound() {
  return (
    <SiteFrame>
      <h1 className="text-lg font-semibold">That investigation is not on this machine</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        The id is missing from the local case file, or it is not a case id.
      </p>
      <Link href="/" className="mt-4 inline-block text-sm underline-offset-4 hover:underline">
        Return to investigations
      </Link>
    </SiteFrame>
  );
}
