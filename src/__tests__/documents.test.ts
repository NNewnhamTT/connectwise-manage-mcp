import { describe, it, expect } from "vitest";
import { decodeBase64, safeFileName, MAX_UPLOAD_BYTES } from "../tools/documents.js";
import { classifyTool } from "../guard/policy.js";

describe("document upload helpers", () => {
  it("decodes valid base64", () => {
    expect(decodeBase64(Buffer.from("hello").toString("base64")).toString()).toBe("hello");
  });

  it("rejects invalid, empty and oversize content", () => {
    expect(() => decodeBase64("not base64!!")).toThrow(/not valid base64/);
    expect(() => decodeBase64("   ")).toThrow(/not valid base64/);
    const big = Buffer.alloc(MAX_UPLOAD_BYTES + 1).toString("base64");
    expect(() => decodeBase64(big)).toThrow(/limit/);
  });

  it("strips paths and control characters from file names", () => {
    expect(safeFileName("C:\\temp\\..\\report.pdf")).toBe("report.pdf");
    expect(safeFileName('a"b\n.txt')).toBe("ab.txt");
    expect(() => safeFileName("dir/")).toThrow();
  });

  it("classifies the upload tool as a write", () => {
    expect(classifyTool("cw_upload_document")).toBe("write");
  });
});
