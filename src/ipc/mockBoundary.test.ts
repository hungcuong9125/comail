import { describe, expect, it } from "vitest";

// The mock engine (src/ipc/mock.ts, ~4k lines of fixtures) must stay out of
// production bundles: release builds contain no mock at all, and dev /
// VITE_MOCK=1 builds load it lazily through `import("./mock")` in
// commands.ts. A static `from ".../mock"` import in app code would drag the
// fixtures back into every build, so this test fails if one reappears.
// Test files are exempt: permanentDelete.test.ts drives mockInvoke directly.

const sources = import.meta.glob("../**/*.{ts,tsx}", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

// Matches `from "<path ending in /mock or exactly ./mock|../mock>"`.
// "./mockMode" and "./mockEvents" do not match: the quote must follow "mock".
const STATIC_MOCK_IMPORT = /from\s+["'][^"']*mock["']/;

describe("mock bundle boundary", () => {
  it("no app source file statically imports the mock engine", () => {
    const offenders = Object.entries(sources)
      .filter(([path]) => !path.endsWith(".test.ts"))
      .filter(([, text]) => STATIC_MOCK_IMPORT.test(text))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it("commands.ts still loads the mock lazily via dynamic import", () => {
    // Glob keys are relative to this file (src/ipc/), so the sibling is "./commands.ts".
    expect(sources["./commands.ts"]).toContain('import("./mock")');
  });
});
