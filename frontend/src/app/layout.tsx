import type { Metadata } from "next";
import "./globals.css";
import "./shell.css";
import { Geist } from "next/font/google";
import { cn } from "@/lib/utils";
import { AssistantWidget } from "@/components/chat/assistant-widget";

const geist = Geist({subsets:['latin'],variable:'--font-sans'});

export const metadata: Metadata = {
  title: "CyberFinGuard",
  description: "Continuous cyber risk quantification and decision intelligence.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en" className={cn("font-sans", geist.variable)} suppressHydrationWarning><body>{children}<AssistantWidget /></body></html>;
}
