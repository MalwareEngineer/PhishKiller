import { useState } from "react";
import { Pencil, Check, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface EditableTextProps {
  value: string | null | undefined;
  onSave: (next: string) => void;
  isPending?: boolean;
  placeholder?: string;
  /** Tailwind class names applied to the rendered (non-editing) span,
   *  e.g. ``text-2xl font-bold`` for the page-title use. */
  displayClassName?: string;
  /** When true, an empty ``value`` is rendered as ``placeholder`` in
   *  italicized muted text (the "click to add" affordance).  Set to
   *  false for required fields like the actor name. */
  allowEmpty?: boolean;
}

/**
 * Inline-editable single-line text.  Pencil-on-hover affordance,
 * Enter to save, Escape to cancel.  Used for actor / family / campaign
 * names + similar header-level fields where the value is already
 * visually prominent and the affordance should be subtle.
 */
export function EditableText({
  value,
  onSave,
  isPending,
  placeholder = "Click to add…",
  displayClassName = "",
  allowEmpty = true,
}: EditableTextProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? "");
  const [previousValue, setPreviousValue] = useState(value);
  if (previousValue !== value) {
    setPreviousValue(value);
    setDraft(value ?? "");
  }

  const commit = () => {
    const next = draft.trim();
    if (!allowEmpty && !next) {
      return;
    }
    onSave(next);
    setEditing(false);
  };

  const cancel = () => {
    setDraft(value ?? "");
    setEditing(false);
  };

  if (editing) {
    return (
      <div className="flex items-center gap-2">
        <Input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") commit();
            else if (e.key === "Escape") cancel();
          }}
          autoFocus
          placeholder={placeholder}
          className="max-w-md"
        />
        <Button
          size="sm"
          variant="ghost"
          className="h-8 px-2"
          onClick={commit}
          disabled={isPending || (!allowEmpty && !draft.trim())}
        >
          <Check className="h-4 w-4" />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="h-8 px-2"
          onClick={cancel}
        >
          <X className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div
      className="group inline-flex items-center gap-2 cursor-pointer"
      onClick={() => setEditing(true)}
    >
      {value ? (
        <span className={displayClassName}>{value}</span>
      ) : (
        <span className="text-sm text-muted-foreground italic">
          {placeholder}
        </span>
      )}
      <Pencil className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
    </div>
  );
}
