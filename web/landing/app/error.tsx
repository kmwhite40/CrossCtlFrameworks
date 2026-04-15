"use client";

import { Button } from "@/components/ui/button";
import { RotateCcw } from "lucide-react";

export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="relative min-h-screen grid place-items-center px-6">
      <div className="text-center max-w-md">
        <div className="font-mono text-sm text-muted-foreground">500</div>
        <h1 className="font-display text-4xl md:text-5xl font-semibold tracking-tight mt-2">Something broke</h1>
        <p className="mt-4 text-muted-foreground">{error.message || "An unexpected error occurred."}</p>
        {error.digest && <div className="mt-2 font-mono text-xs text-muted-foreground">ref: {error.digest}</div>}
        <div className="mt-8">
          <Button variant="secondary" onClick={() => reset()}><RotateCcw /> Try again</Button>
        </div>
      </div>
    </main>
  );
}
