import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatPct(n: number) {
  return `${Math.round(n * 100)}%`;
}

export function displayUrl(url: string) {
  return url;
}

export function verdictLabel(v: string) {
  if (v === "phishing") return "PHISHING";
  if (v === "suspicious") return "SUSPICIOUS";
  return "LEGITIMATE";
}
