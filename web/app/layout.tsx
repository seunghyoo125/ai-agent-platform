import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ai-agent-platform",
  description: "Enterprise AI agent quality shell"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
