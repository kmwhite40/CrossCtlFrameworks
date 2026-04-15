import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <main className="relative min-h-screen grid place-items-center px-6">
      <div className="text-center max-w-md">
        <div className="font-mono text-sm text-muted-foreground">404</div>
        <h1 className="font-display text-4xl md:text-5xl font-semibold tracking-tight mt-2">Page not found</h1>
        <p className="mt-4 text-muted-foreground">
          The page you were looking for doesn&apos;t exist or has moved.
        </p>
        <div className="mt-8">
          <Button asChild variant="secondary"><Link href="/"><ArrowLeft /> Back to home</Link></Button>
        </div>
      </div>
    </main>
  );
}
