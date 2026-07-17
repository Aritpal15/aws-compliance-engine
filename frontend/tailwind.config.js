/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        canvas: {
          light: "#F5F5F7",
          dark: "#000000", // Pure Pitch Black Canvas
        },
        panel: {
          light: "#FFFFFF",
          dark: "#0D0D0D", // Rich Obsidian Panel Background
        },
        borderToken: {
          light: "#E2E8F0",
          dark: "#1F1F1F", // Crisp Border Division Line
        },
        textToken: {
          light: "#1E293B",
          dark: "#EDEDED",
        },
        critical: {
          light: "#DC3545",
          dark: "#FF4A5A",
        },
        warning: {
          light: "#D97706",
          dark: "#FFB020",
        },
      },
    },
  },
  plugins: [],
};
