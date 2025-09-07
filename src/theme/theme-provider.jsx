"use client";

import * as React from "react";
import { ThemeProvider as NextThemesProvider } from "next-themes";

export function ThemeProvider({ children }) {
  return (
    <NextThemesProvider
      attribute="class"       // ✅ applies `class="dark"` on <html>
      defaultTheme="light"    // ✅ starts in light mode
      enableSystem={true}     // ✅ detects system preference
      disableTransitionOnChange
    >
      {children}
    </NextThemesProvider>
  );
}
