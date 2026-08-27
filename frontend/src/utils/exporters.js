// CSV/JSON export helpers shared by every table panel. Same Blob + object URL
// pattern already used by MonitorMatchesPanel.downloadJson - kept in one place
// so any table can offer an export without duplicating it.

function stringifyCell(value) {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.join(" | ");
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "";
    }
  }
  return String(value);
}

function escapeCsvCell(value) {
  const text = stringifyCell(value);
  if (/["\n\r,]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

export function slugify(value, fallback = "export") {
  const cleaned = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || fallback;
}

export function rowsToCsv(rows, columns) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const safeColumns = Array.isArray(columns) ? columns.filter((column) => column && column.key) : [];
  if (!safeColumns.length) return "";
  const header = safeColumns.map((column) => escapeCsvCell(column.label || column.key)).join(",");
  const body = safeRows.map((row) =>
    safeColumns
      .map((column) =>
        escapeCsvCell(typeof column.value === "function" ? column.value(row) : row && row[column.key])
      )
      .join(",")
  );
  return [header, ...body].join("\r\n");
}

export function downloadTextFile(filename, text, mimeType = "text/plain") {
  if (typeof document === "undefined" || typeof URL === "undefined") return false;
  const blob = new Blob([text], { type: `${mimeType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  return true;
}

export function buildExportFilename(title, extension) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `sniff4hound-${slugify(title, "table")}-${stamp}.${extension}`;
}

export default { rowsToCsv, downloadTextFile, buildExportFilename, slugify };
