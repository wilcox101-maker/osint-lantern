import Link from "next/link";

export function SiteFrame({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto flex min-h-screen w-full max-w-6xl flex-col px-4 py-6 sm:px-6">
      <header className="mb-8 flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <Link href="/" className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-md bg-primary text-sm font-semibold tracking-tight text-primary-foreground">
            Ln
          </span>
          <span>
            <span className="block text-base font-semibold tracking-tight">Lantern</span>
            <span className="block text-xs text-muted-foreground">Public-source investigations</span>
          </span>
        </Link>
        <nav className="flex items-center gap-4 text-sm">
          <Link href="/" className="text-foreground/80 hover:text-foreground">
            Investigations
          </Link>
          <Link href="/catalog" className="text-foreground/80 hover:text-foreground">
            Module catalog
          </Link>
        </nav>
      </header>
      <main className="flex-1">{children}</main>
      <footer className="mt-12 border-t border-border pt-4 text-xs text-muted-foreground">
        Findings cite the source that produced them. Lantern does not run exploits, look up national IDs, or return passwords.
      </footer>
    </div>
  );
}
