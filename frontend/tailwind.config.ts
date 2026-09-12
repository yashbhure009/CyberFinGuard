import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        ink: "#17212b",
        muted: "#647482",
        canvas: "#f5f7f9",
        accent: "#146c94",
      },
    },
  },
  plugins: [],
};

export default config;
