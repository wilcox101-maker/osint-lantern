"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { modulesFor } from "@/lib/osint/catalog";
import { classifySelector, selectorLabel } from "@/lib/osint/classify";

export function NewInvestigation() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [notes, setNotes] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const classified = useMemo(
    () => (query.trim() ? classifySelector(query) : null),
    [query],
  );
  const planned =
    classified?.ok === true ? modulesFor(classified.kind, password.trim().length > 0) : [];

  async function submit(nextQuery: string, includeSecret: boolean) {
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/investigations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          query: nextQuery,
          notes: includeSecret ? notes : "",
          password: includeSecret ? password : "",
        }),
      });
      const payload = (await response.json()) as { id?: string; error?: string };
      if (!response.ok || !payload.id) {
        setError(payload.error ?? "The investigation did not start.");
        return;
      }
      setPassword("");
      router.push(`/investigations/${payload.id}`);
      router.refresh();
    } catch {
      setError("Lantern could not reach its own API. The dev server may still be starting.");
    } finally {
      setPending(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Open an investigation</CardTitle>
        <CardDescription>
          Enter an email, website, public IP, username, or phone number with a country code. Lantern reads public sources and, for a domain, makes one request to that site for headers and well-known files.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (!classified || !classified.ok || pending) return;
            void submit(query, true);
          }}
        >
          <div className="flex flex-col gap-2">
            <Label htmlFor="target">Target</Label>
            <Input
              id="target"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="ada@example.com or example.com"
              autoComplete="off"
              spellCheck={false}
              className="h-11 font-mono"
              aria-invalid={classified?.ok === false}
            />
            {classified?.ok === true ? (
              <p className="text-xs text-muted-foreground">
                Read as <span className="text-foreground">{selectorLabel(classified.kind)}</span>
                {" · "}
                <span className="font-mono">{classified.value}</span>
              </p>
            ) : null}
            {classified?.ok === false ? (
              <p className="text-xs text-destructive">{classified.error}</p>
            ) : null}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col gap-2">
              <Label htmlFor="notes">Case notes</Label>
              <Textarea
                id="notes"
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                placeholder="Why this target is in scope. Stored with the case."
                maxLength={2000}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="password">Password you already know</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Optional range check"
                autoComplete="off"
                className="h-11"
              />
              <p className="text-xs text-muted-foreground">
                Hashed locally. Only five characters of the SHA-1 go to the Pwned Passwords range API. The password is not written to the case file.
              </p>
            </div>
          </div>
          {planned.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {planned.map((item) => (
                <Badge key={item.id} variant="outline">
                  {item.title}
                </Badge>
              ))}
            </div>
          ) : null}
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" size="lg" disabled={pending || classified?.ok !== true}>
              {pending ? "Reading public sources…" : "Run investigation"}
            </Button>
            <Button
              type="button"
              size="lg"
              variant="outline"
              disabled={pending}
              onClick={() => {
                setQuery("example.com");
                void submit("example.com", false);
              }}
            >
              Try example.com
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
