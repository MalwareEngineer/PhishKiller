// Thin React wrapper around CodeMirror 6 with the YARA mode applied.
import { useEffect, useRef } from "react";
import { EditorState, Compartment } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { bracketMatching, indentOnInput, syntaxHighlighting, defaultHighlightStyle } from "@codemirror/language";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { yaraLanguage } from "@/lib/yara-codemirror";

interface YaraEditorProps {
  value: string;
  onChange: (next: string) => void;
  height?: string;
  readOnly?: boolean;
}

const themeCompartment = new Compartment();

export function YaraEditor({ value, onChange, height = "420px", readOnly = false }: YaraEditorProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  // Initial mount — set up the editor exactly once.
  useEffect(() => {
    if (!containerRef.current) return;

    const state = EditorState.create({
      doc: value,
      extensions: [
        lineNumbers(),
        history(),
        bracketMatching(),
        indentOnInput(),
        highlightActiveLine(),
        highlightSelectionMatches(),
        keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, indentWithTab]),
        yaraLanguage,
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        EditorView.editable.of(!readOnly),
        EditorState.readOnly.of(readOnly),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            onChangeRef.current(update.state.doc.toString());
          }
        }),
        themeCompartment.of(EditorView.theme({
          "&": { height, fontSize: "13px" },
          ".cm-scroller": { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace" },
          ".cm-content": { caretColor: "var(--foreground)" },
          ".cm-gutters": { backgroundColor: "transparent", borderRight: "1px solid var(--border)" },
        })),
      ],
    });

    const view = new EditorView({ state, parent: containerRef.current });
    viewRef.current = view;
    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // Mount-once: deps intentionally empty.  Subsequent value changes go
    // through the second effect below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Keep the editor in sync if the parent replaces the buffer (e.g. loading
  // a saved rule).  Skip when the value already matches to avoid clobbering
  // the cursor on every keystroke.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const current = view.state.doc.toString();
    if (current === value) return;
    view.dispatch({
      changes: { from: 0, to: current.length, insert: value },
    });
  }, [value]);

  return (
    <div
      ref={containerRef}
      className="border border-border rounded-md overflow-hidden bg-background"
      style={{ height }}
    />
  );
}
