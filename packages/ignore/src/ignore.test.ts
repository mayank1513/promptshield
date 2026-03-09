/** biome-ignore-all lint/suspicious/noExplicitAny: test file */
import { describe, expect, it } from "vitest";
import { createIgnoreChecker, filterThreats } from "./ignore";

const threat = (line: number) =>
  ({
    range: {
      start: { line, column: 1, index: line * 10 },
      end: { line, column: 1, index: line * 10 },
    },
    severity: "HIGH",
  }) as any;

describe("filterThreats", () => {
  it("returns threats unchanged when no ignore directives exist", () => {
    const text = "hello\nworld";
    const threats = [threat(1), threat(2)];

    const result = filterThreats(text, threats);

    expect(result.threats).toHaveLength(2);
    expect(result.unusedIgnores).toHaveLength(0);
  });

  it("ignores inline directive", () => {
    const text = "foo(); // promptshield-ignore";
    const threats = [threat(1)];

    const result = filterThreats(text, threats);

    expect(result.threats).toHaveLength(0);
    expect(result.unusedIgnores).toHaveLength(0);
  });

  it("ignores next line via comment-only directive", () => {
    const text = `
# promptshield-ignore
danger()
`.trim();

    const threats = [threat(2)];

    const result = filterThreats(text, threats);

    expect(result.threats).toHaveLength(0);
  });

  it("supports 'next N' directive", () => {
    const text = `
promptshield-ignore next 2
a()
b()
c()
`.trim();

    const threats = [threat(2), threat(3), threat(4)];

    const result = filterThreats(text, threats);

    expect(result.threats.map((t) => t.range.start.line)).toEqual([4]);
  });

  it("supports ignore file directive", () => {
    const text = `
promptshield-ignore all
foo()
bar()
`.trim();

    const threats = [threat(2), threat(3)];

    const result = filterThreats(text, threats);

    expect(result.threats).toHaveLength(0);
  });

  it("reports unused ignore directives", () => {
    const text = `
promptshield-ignore next 2
safe()
safe()
`.trim();

    const threats: any[] = [];

    const result = filterThreats(text, threats);

    expect(result.unusedIgnores.length).toBe(1);
  });

  it("handles multiple ignore ranges", () => {
    const text = `
promptshield-ignore next
a()
promptshield-ignore next
b()
c()
`.trim();

    const threats = [threat(2), threat(4), threat(5)];

    const result = filterThreats(text, threats);

    expect(result.threats.map((t) => t.range.start.line)).toEqual([5]);
  });

  it("handles unsorted threat input", () => {
    const text = `
promptshield-ignore next
danger()
`.trim();

    const threats = [threat(2), threat(1)];

    const result = filterThreats(text, threats);

    expect(result.threats.map((t) => t.range.start.line)).toEqual([1]);
  });

  it("respects noInlineIgnore option to bypass directives", () => {
    const text = `
promptshield-ignore all
danger()
`.trim();

    const threats = [threat(2)];
    const result = filterThreats(text, threats, { noInlineIgnore: true });

    expect(result.threats).toHaveLength(1);
    expect(result.ignoredThreats).toHaveLength(0);
  });

  describe("createIgnoreChecker", () => {
    it("returns true for all offsets if ignore-all is present", () => {
      const text = "promptshield-ignore all\ndanger()";
      const checker = (createIgnoreChecker as any)(text);
      expect(checker(0, 100)).toBe(true);
      expect(checker(25, 30)).toBe(true);
    });

    it("ignores correctly for single line ignore", () => {
      const text = "safe()\ndanger() // promptshield-ignore\nmore_safe()";
      const checker = (createIgnoreChecker as any)(text);
      // "safe()" is line 1 -> offsets 0-6
      // "danger..." is line 2 -> offsets 7-36
      expect(checker(0, 5)).toBe(false);
      expect(checker(8, 15)).toBe(true);
      expect(checker(40, 50)).toBe(false);
    });

    it("ignores correctly for standalone comment (next line)", () => {
      const text = "// promptshield-ignore\ndanger()\nsafe()";
      const checker = (createIgnoreChecker as any)(text);
      // Comment is line 1. danger() is line 2.
      expect(checker(23, 30)).toBe(true); // danger()
      expect(checker(32, 38)).toBe(false); // safe()
    });

    it("supports ignore next N lines", () => {
      const text = "promptshield-ignore next 2\ndanger1()\ndanger2()\nsafe()";
      const checker = (createIgnoreChecker as any)(text);
      expect(checker(27, 35)).toBe(true); // danger1()
      expect(checker(37, 45)).toBe(true); // danger2()
      expect(checker(47, 53)).toBe(false); // safe()
    });

    it("merges overlapping and adjacent ignore ranges", () => {
      const text = `
promptshield-ignore next 1
danger1()
promptshield-ignore next 1
danger2()
`.trim();
      const checker = (createIgnoreChecker as any)(text);
      // Line 1: ignore next 1 (ignores line 2)
      expect(checker(27, 34)).toBe(true); // danger1() at line 2
    });
  });
});
