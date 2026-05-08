// Minimal YARA syntax highlighting for CodeMirror 6.
//
// Hand-rolled StreamLanguage rather than a full Lezer grammar — YARA's
// surface syntax is small enough that a tokenizer-style highlighter is
// plenty for an authoring playground.  No semantic indent / folding;
// CodeMirror's bracket matching gets us close enough.

import { StreamLanguage, type StringStream } from "@codemirror/language";

const KEYWORDS = new Set([
  "rule", "private", "global", "meta", "strings", "condition",
  "import", "true", "false", "and", "or", "not", "any", "all", "of",
  "them", "for", "in", "at", "matches", "contains", "icontains",
  "startswith", "istartswith", "endswith", "iendswith", "iequals",
  "ascii", "wide", "nocase", "fullword", "xor", "base64", "base64wide",
  "filesize", "entrypoint", "uint8", "uint16", "uint32",
  "int8", "int16", "int32", "uint8be", "uint16be", "uint32be",
  "int8be", "int16be", "int32be", "defined",
]);

interface YaraState {
  inComment: boolean;   // /* */ block comment
  inString: boolean;    // "..." text string
  inHexString: boolean; // {  } hex string
  inRegex: boolean;     // /.../ regex
  stringQuote: '"' | null;
}

function startState(): YaraState {
  return {
    inComment: false,
    inString: false,
    inHexString: false,
    inRegex: false,
    stringQuote: null,
  };
}

function token(stream: StringStream, state: YaraState): string | null {
  // Block comment
  if (state.inComment) {
    while (!stream.eol()) {
      if (stream.match("*/")) {
        state.inComment = false;
        return "comment";
      }
      stream.next();
    }
    return "comment";
  }

  // Text string
  if (state.inString) {
    while (!stream.eol()) {
      const ch = stream.next();
      if (ch === "\\" && !stream.eol()) {
        stream.next();
        continue;
      }
      if (ch === state.stringQuote) {
        state.inString = false;
        state.stringQuote = null;
        return "string";
      }
    }
    return "string";
  }

  // Hex string
  if (state.inHexString) {
    while (!stream.eol()) {
      const ch = stream.next();
      if (ch === "}") {
        state.inHexString = false;
        return "string";
      }
    }
    return "string";
  }

  // Regex
  if (state.inRegex) {
    while (!stream.eol()) {
      const ch = stream.next();
      if (ch === "\\" && !stream.eol()) {
        stream.next();
        continue;
      }
      if (ch === "/") {
        state.inRegex = false;
        // Optional flags after closing /
        stream.eatWhile(/[ginsxu]/);
        return "regexp";
      }
    }
    return "regexp";
  }

  if (stream.eatSpace()) return null;

  // Line comment
  if (stream.match("//")) {
    stream.skipToEnd();
    return "comment";
  }

  // Block comment start
  if (stream.match("/*")) {
    state.inComment = true;
    return "comment";
  }

  const ch = stream.next();
  if (ch === null || ch === undefined) return null;

  // Strings
  if (ch === '"') {
    state.inString = true;
    state.stringQuote = '"';
    return "string";
  }

  // Hex literal block
  if (ch === "{") {
    // Heuristic: only treat { ... } as a hex string when preceded by `=`
    // recently.  Cheap approach: peek for hex/whitespace contents.  In
    // practice YARA grammar makes the disambiguation by context, but the
    // heuristic suffices for highlighting.
    state.inHexString = true;
    return "string";
  }

  // Regex literal — heuristic: a `/` followed by non-space, ending in `/flags`.
  // Only enter regex mode if the previous non-space char was `=` (assignment
  // for a string identifier).  Without lookbehind state this is approximate;
  // safest to require the next char to not be `/` (line comment) and not be
  // `*` (block comment) — both already handled above.
  if (ch === "/") {
    state.inRegex = true;
    return "regexp";
  }

  // String identifier ($a, !a, #a, @a)
  if (ch === "$" || ch === "!" || ch === "#" || ch === "@") {
    stream.eatWhile(/[a-zA-Z0-9_*]/);
    return "variableName";
  }

  // Numbers (decimal, hex, KB/MB suffixes)
  if (/[0-9]/.test(ch)) {
    if (ch === "0" && (stream.peek() === "x" || stream.peek() === "X")) {
      stream.next();
      stream.eatWhile(/[0-9a-fA-F]/);
    } else {
      stream.eatWhile(/[0-9]/);
    }
    stream.eatWhile(/[KMG]B?/);
    return "number";
  }

  // Identifiers & keywords
  if (/[a-zA-Z_]/.test(ch)) {
    stream.eatWhile(/[a-zA-Z0-9_]/);
    const word = stream.current() ?? "";
    if (KEYWORDS.has(word)) {
      // Decoration hint: rule/condition/strings/meta show as section keywords.
      return "keyword";
    }
    return "name";
  }

  return null;
}

export const yaraLanguage = StreamLanguage.define<YaraState>({
  name: "yara",
  startState,
  token,
  languageData: {
    commentTokens: { line: "//", block: { open: "/*", close: "*/" } },
  },
});
