import type { Metadata } from "next";
import { Inter, Space_Grotesk } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" });
const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  display: "swap",
  weight: ["500", "600", "700"],
});

export const metadata: Metadata = {
  title: {
    default: "Concord — Cross-framework compliance, in concord",
    template: "%s · Concord",
  },
  description:
    "Ingest every NIST 800-53A assessment objective, map it to every major compliance framework, and run your whole control program from one place.",
  metadataBase: new URL("http://localhost:3000"),
  applicationName: "Concord",
  authors: [{ name: "Colleen Townsend" }],
  keywords: [
    "compliance", "NIST 800-53", "FedRAMP", "FISMA", "CMMC",
    "ISO 27001", "SOC 2", "HIPAA", "POA&M", "OSCAL",
  ],
  openGraph: {
    title: "Concord — Cross-framework compliance, in concord",
    description:
      "NIST 800-53A Rev 5 + 26 framework crosswalks + compliance-ops layer in a single service.",
    url: "http://localhost:3000",
    siteName: "Concord",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Concord — Cross-framework compliance, in concord",
    description: "NIST 800-53A Rev 5 + 26 framework crosswalks in one service.",
  },
  icons: {
    icon: "/favicon.svg",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${spaceGrotesk.variable}`}>
      <body className="min-h-screen bg-background font-sans text-foreground">
        {children}
      </body>
    </html>
  );
}
