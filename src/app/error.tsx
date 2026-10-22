"use client";

import { useEffect } from "react";

import { SiteFrame } from "@/components/site-frame";
import { Button } from "@/components/ui/button";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <SiteFrame>
      <h1 className="text-lg font-semibold">The case file could not be read</h1>
      <p className="mt-2 max-w-xl text-sm text-muted-foreground">
        {error.message || "Something went wrong while loading Lantern."}
      </p>
      <Button type="button" className="mt-4" onClick={() => reset()}>
        Try again
      </Button>
    </SiteFrame>
  );
}
