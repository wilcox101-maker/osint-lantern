import type { Metadata } from "next";

import { SiteFrame } from "@/components/site-frame";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { CATALOG_MODULES, OUT_OF_SCOPE } from "@/lib/osint/catalog";
import { selectorLabel } from "@/lib/osint/classify";

export const metadata: Metadata = {
  title: "Module catalog",
  description: "Passive modules Lantern runs, and the public pentester.com capabilities they correspond to.",
};

export default function CatalogPage() {
  return (
    <SiteFrame>
      <div className="flex max-w-3xl flex-col gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Module catalog</h1>
        <p className="text-sm text-muted-foreground">
          On 21 Oct 2026, REA 6.7.0 attached to a local Chrome and inspected the public pages of pentester.com, its breach checker, services page, FAQ, NPD notice, login screen, and OSINT Pilot. Accessibility text was collected. Script source and browser storage were not. A bundle analysis of the signed-in app ran out of memory, so those private routes were left alone.
        </p>
        <p className="text-sm text-muted-foreground">
          Lantern implements the passive slice of what those pages describe: footprint, breach titles, profile URLs, and a sourced report. It is a separate program. It does not call pentester.com.
        </p>
      </div>
      <div className="mt-6 grid gap-3">
        {CATALOG_MODULES.map((item) => (
          <Card key={item.id}>
            <CardHeader>
              <div className="flex flex-wrap gap-2">
                {item.selectors.map((selector) => (
                  <Badge key={selector} variant="secondary">
                    {selectorLabel(selector)}
                  </Badge>
                ))}
                {item.requiresPassword ? <Badge variant="outline">Optional password</Badge> : null}
              </div>
              <CardTitle>{item.title}</CardTitle>
              <CardDescription>{item.does}</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">Observed as: {item.observed}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <h2 className="mt-10 text-lg font-semibold">Left out on purpose</h2>
      <div className="mt-3 grid gap-3">
        {OUT_OF_SCOPE.map((item) => (
          <Card key={item.name}>
            <CardHeader>
              <CardTitle>{item.name}</CardTitle>
              <CardDescription>{item.why}</CardDescription>
            </CardHeader>
          </Card>
        ))}
      </div>
    </SiteFrame>
  );
}
