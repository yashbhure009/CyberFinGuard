import type { Metadata } from "next";
import "./globals.css";
import "./shell.css";

export const metadata: Metadata = {
  title: "CyberFinGuard",
  description: "Continuous cyber risk quantification and decision intelligence.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
