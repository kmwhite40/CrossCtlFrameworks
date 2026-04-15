import ShaderBackground from "@/components/ui/shader-background";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ArrowRight,
  ShieldCheck,
  Layers,
  Workflow,
  FileSpreadsheet,
  Github,
  Sparkles,
  Lock,
  ScanLine,
  FileText,
} from "lucide-react";
import Link from "next/link";
import Image from "next/image";

const FRAMEWORKS = [
  "NIST 800-53 Rev 5",
  "NIST 800-53A Rev 5",
  "NIST 800-171 R2/R3",
  "NIST 800-172",
  "NIST CSF 1.1 / 2.0",
  "FedRAMP",
  "StateRAMP",
  "CMMC Rev 2",
  "FISMA",
  "CJIS",
  "MARS-E",
  "HIPAA",
  "HITRUST",
  "ISO 27001",
  "SOC 2",
  "CIS v8",
  "CSA CCM",
  "GDPR",
  "AWS / Azure / GCP",
  "CUI Overlay",
] as const;

const FEATURES = [
  {
    icon: Layers,
    title: "Every control, every framework",
    body:
      "Ingest the NIST Cross Mappings workbook once. 5,400+ 800-53A objectives mapped to 26 canonical frameworks across 121,000 crosswalks.",
  },
  {
    icon: Workflow,
    title: "Compliance operations built-in",
    body:
      "Organizations, systems (FIPS-199 + FedRAMP baselines), per-system control implementations, evidence, assessments, POA&Ms, risks — audited.",
  },
  {
    icon: ScanLine,
    title: "Search everything",
    body:
      "Postgres full-text search across identifiers, names, objectives, and discussion. Find any control or assessment procedure in milliseconds.",
  },
  {
    icon: FileText,
    title: "Custom reports",
    body:
      "Scope a report by organization, system, baseline, family, or crosswalk framework — export JSON or CSV ready for audit packages.",
  },
  {
    icon: Lock,
    title: "Enterprise-grade by default",
    body:
      "Typed schema + JSONB audit trail, SHA-256 provenance, Alembic migrations, non-root container, SBOM + Trivy in CI, append-only audit log.",
  },
  {
    icon: FileSpreadsheet,
    title: "OpenAPI everywhere",
    body:
      "Everything the UI renders is also JSON under /api. Swagger at /docs. Build dashboards, pipelines, and integrations without touching the DB.",
  },
];

const STEPS = [
  {
    n: "01",
    title: "Ingest the workbook",
    body:
      "One docker compose command loads 17 sheets into Postgres, normalizes the assessment catalog, and classifies every mapping column.",
  },
  {
    n: "02",
    title: "Model your program",
    body:
      "Create organizations, authorization boundaries, and implementation state per control. Attach evidence, plan remediations, track findings.",
  },
  {
    n: "03",
    title: "Export & answer auditors",
    body:
      "Generate CSV / JSON reports scoped to a specific framework or baseline. Every ingestion is hashed and logged for provenance.",
  },
];

export default function Page() {
  return (
    <>
      <ShaderBackground />

      <div className="relative">
        {/* ── Nav ───────────────────────────────────────────── */}
        <header className="sticky top-0 z-20 backdrop-blur-md bg-background/30 border-b border-border/50">
          <div className="container flex h-16 items-center">
            <Link href="/" className="flex items-center gap-2">
              <div className="grid h-8 w-8 place-items-center rounded-lg bg-primary/90 text-primary-foreground font-semibold shadow-[0_0_20px_rgba(168,85,247,0.5)]">
                C
              </div>
              <span className="font-display text-lg font-semibold tracking-tight">Concord</span>
              <Badge variant="secondary" className="ml-2 hidden md:inline-flex">v0.1 · preview</Badge>
            </Link>
            <nav className="ml-auto hidden items-center gap-6 md:flex text-sm text-muted-foreground">
              <Link href="#features" className="hover:text-foreground">Features</Link>
              <Link href="#frameworks" className="hover:text-foreground">Frameworks</Link>
              <Link href="#how" className="hover:text-foreground">How it works</Link>
              <Link href="http://localhost:8088" className="hover:text-foreground">Open app</Link>
            </nav>
            <div className="ml-4 flex items-center gap-2">
              <Button asChild variant="ghost" size="sm" className="hidden md:inline-flex">
                <Link href="https://github.com/kmwhite40/CrossCtlFrameworks" target="_blank">
                  <Github /> GitHub
                </Link>
              </Button>
              <Button asChild size="sm">
                <Link href="http://localhost:8088">Launch Concord <ArrowRight /></Link>
              </Button>
            </div>
          </div>
        </header>

        {/* ── Hero ──────────────────────────────────────────── */}
        <section className="relative container flex flex-col items-center text-center pt-28 pb-32">
          <Badge className="mb-6 animate-fade-in">
            <Sparkles className="mr-1 h-3.5 w-3.5" />
            NIST 800-53A Rev 5 + 26 frameworks, one schema
          </Badge>
          <h1 className="font-display text-balance text-5xl md:text-7xl font-semibold tracking-tight leading-[1.05] animate-fade-in">
            Cross-framework compliance,
            <br />
            <span className="gradient-text">in concord.</span>
          </h1>
          <p className="mt-6 max-w-2xl text-balance text-lg text-muted-foreground animate-fade-in">
            Ingest every NIST 800-53A assessment objective, map it to every major
            compliance framework, and run your entire control program from one
            place — without losing the raw audit trail.
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3 animate-fade-in">
            <Button asChild size="lg">
              <Link href="http://localhost:8088">Launch Concord <ArrowRight /></Link>
            </Button>
            <Button asChild variant="outline" size="lg">
              <Link href="#how">How it works</Link>
            </Button>
          </div>

          <div className="mt-16 grid w-full grid-cols-2 gap-4 md:grid-cols-4 text-left">
            {[
              { k: "5,430", v: "control objectives" },
              { k: "121,944", v: "framework mappings" },
              { k: "26", v: "canonical frameworks" },
              { k: "17", v: "workbook tabs ingested" },
            ].map((s) => (
              <Card key={s.v} className="animate-fade-in">
                <CardContent className="p-5">
                  <div className="font-display text-3xl font-semibold tracking-tight">{s.k}</div>
                  <div className="mt-1 text-sm text-muted-foreground">{s.v}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        {/* ── Features ──────────────────────────────────────── */}
        <section id="features" className="container py-24">
          <div className="flex flex-col items-center text-center">
            <Badge variant="outline" className="mb-4">Features</Badge>
            <h2 className="font-display text-4xl md:text-5xl font-semibold tracking-tight text-balance">
              Built for the real work of compliance
            </h2>
            <p className="mt-4 max-w-2xl text-muted-foreground text-balance">
              A typed catalog plus an operational layer — not just a lookup table.
            </p>
          </div>

          <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f) => (
              <Card key={f.title} className="transition-transform hover:-translate-y-0.5">
                <CardHeader>
                  <div className="mb-3 grid h-10 w-10 place-items-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
                    <f.icon className="h-5 w-5" />
                  </div>
                  <CardTitle>{f.title}</CardTitle>
                  <CardDescription className="text-[0.925rem] leading-relaxed">{f.body}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </section>

        {/* ── Frameworks ────────────────────────────────────── */}
        <section id="frameworks" className="container py-24">
          <div className="flex flex-col items-center text-center">
            <Badge variant="outline" className="mb-4"><ShieldCheck className="mr-1 h-3.5 w-3.5" /> 26 frameworks</Badge>
            <h2 className="font-display text-4xl md:text-5xl font-semibold tracking-tight text-balance">
              Every crosswalk, one query away
            </h2>
            <p className="mt-4 max-w-2xl text-muted-foreground text-balance">
              Mappings are normalized into a tall table, not buried in JSONB, so you can query
              coverage in SQL, group by family, or export a single-framework readiness packet.
            </p>
          </div>

          <div className="mt-12 flex flex-wrap justify-center gap-2">
            {FRAMEWORKS.map((f) => (
              <Badge key={f} variant="secondary" className="px-3 py-1.5 text-[0.8rem]">
                {f}
              </Badge>
            ))}
          </div>
        </section>

        {/* ── How it works ──────────────────────────────────── */}
        <section id="how" className="container py-24">
          <div className="flex flex-col items-center text-center">
            <Badge variant="outline" className="mb-4">How it works</Badge>
            <h2 className="font-display text-4xl md:text-5xl font-semibold tracking-tight text-balance">
              Three steps from xlsx to audit-ready
            </h2>
          </div>

          <div className="mt-12 grid gap-4 md:grid-cols-3">
            {STEPS.map((s) => (
              <Card key={s.n}>
                <CardContent className="p-6">
                  <div className="font-mono text-xs text-muted-foreground">{s.n}</div>
                  <div className="mt-2 font-display text-xl font-semibold">{s.title}</div>
                  <p className="mt-2 text-sm text-muted-foreground leading-relaxed">{s.body}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>

        {/* ── Preview strip ─────────────────────────────────── */}
        <section className="container py-24">
          <Card className="overflow-hidden">
            <div className="grid items-center gap-0 md:grid-cols-2">
              <div className="p-10">
                <Badge variant="outline" className="mb-4">Preview</Badge>
                <h3 className="font-display text-3xl font-semibold tracking-tight text-balance">
                  A polished operator console
                </h3>
                <p className="mt-4 text-muted-foreground">
                  Dashboards, faceted control browser, per-control detail with grouped
                  mappings, framework catalog, generic worksheet viewer, full-text search,
                  and a custom report builder — all in one FastAPI service at
                  <span className="mx-1 font-mono text-xs">localhost:8088</span>.
                </p>
                <div className="mt-6 flex gap-2">
                  <Button asChild>
                    <Link href="http://localhost:8088">Open Concord <ArrowRight /></Link>
                  </Button>
                  <Button asChild variant="outline">
                    <Link href="http://localhost:8088/docs">API docs</Link>
                  </Button>
                </div>
              </div>
              <div className="relative aspect-[16/11] md:aspect-auto md:h-full">
                <Image
                  src="https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1600&q=80"
                  alt="Server rack and cables — representative of a compliance boundary"
                  fill
                  sizes="(min-width: 768px) 50vw, 100vw"
                  className="object-cover"
                  priority={false}
                />
                <div className="absolute inset-0 bg-gradient-to-l from-transparent to-background/80" />
              </div>
            </div>
          </Card>
        </section>

        {/* ── CTA ───────────────────────────────────────────── */}
        <section className="container py-24">
          <Card className="relative overflow-hidden">
            <div className="absolute -top-24 -right-24 h-64 w-64 rounded-full bg-primary/30 blur-3xl" aria-hidden="true" />
            <div className="relative p-10 md:p-14 text-center">
              <h3 className="font-display text-3xl md:text-4xl font-semibold tracking-tight text-balance">
                Ready to see it in action?
              </h3>
              <p className="mx-auto mt-4 max-w-xl text-muted-foreground text-balance">
                Stand up Concord with a single <span className="font-mono text-xs">docker compose up</span>.
                Load the workbook. Open the UI. You're done.
              </p>
              <div className="mt-8 flex flex-wrap justify-center gap-2">
                <Button asChild size="lg">
                  <Link href="http://localhost:8088">Launch Concord <ArrowRight /></Link>
                </Button>
                <Button asChild size="lg" variant="outline">
                  <Link href="https://github.com/kmwhite40/CrossCtlFrameworks" target="_blank">
                    <Github /> View on GitHub
                  </Link>
                </Button>
              </div>
            </div>
          </Card>
        </section>

        {/* ── Footer ────────────────────────────────────────── */}
        <footer className="border-t border-border/50 py-10">
          <div className="container flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
            <div>© 2026 Colleen Townsend. All rights reserved.</div>
            <div className="flex items-center gap-5">
              <Link href="http://localhost:8088" className="hover:text-foreground">App</Link>
              <Link href="http://localhost:8088/docs" className="hover:text-foreground">API</Link>
              <Link href="https://github.com/kmwhite40/CrossCtlFrameworks" target="_blank" className="hover:text-foreground">GitHub</Link>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
}
