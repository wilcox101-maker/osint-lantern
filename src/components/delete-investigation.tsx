"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";

export function DeleteInvestigation({ id }: { id: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="flex flex-col items-end gap-2">
      <Button
        type="button"
        variant="outline"
        disabled={pending}
        onClick={() => {
          void (async () => {
            setPending(true);
            setError(null);
            const response = await fetch(`/api/investigations/${id}`, { method: "DELETE" });
            if (!response.ok) {
              setError("The case file could not be deleted.");
              setPending(false);
              return;
            }
            router.push("/");
            router.refresh();
          })();
        }}
      >
        {pending ? "Deleting…" : "Delete case"}
      </Button>
      {error ? <p className="text-xs text-destructive">{error}</p> : null}
    </div>
  );
}
