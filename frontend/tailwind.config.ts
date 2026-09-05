import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#070b12",
        panel: "#0e1624",
        line: "#1c2a40",
        mint: "#3ee0b0",
        warn: "#f5b942",
        danger: "#ff5d6c",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "Segoe UI", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glass: "0 0 0 1px rgba(255,255,255,0.04), 0 20px 50px rgba(0,0,0,0.35)",
      },
    },
  },
  plugins: [],
} satisfies Config;
