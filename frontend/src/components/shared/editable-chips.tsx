import { useState, type ReactNode } from "react";
import { Pencil, X, Plus } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface EditableChipsProps {
  /** The current array of values.  ``null`` is rendered as empty. */
  value: string[] | null | undefined;
  /** Save handler.  Receives the new array (already de-duped + trimmed).
   *  Pass an empty array to clear the field. */
  onSave: (next: string[]) => void;
  isPending?: boolean;
  /** Placeholder shown in the add-chip input. */
  placeholder?: string;
  /** Optional label rendered above the chips.  ReactNode so callers
   *  can include an inline icon (e.g. ``<Mail/> Email addresses``). */
  label?: ReactNode;
  /** Empty-state copy when ``value`` is empty AND not editing. */
  emptyText?: string;
  /** Lower-case input on save.  Useful for emails / domains where
   *  "Alice@Acme.com" and "alice@acme.com" should converge. */
  lowercase?: boolean;
  /** Restricted character set passed through to ``inputMode``.  Used
   *  to nudge the soft-keyboard for telegram/email. */
  inputMode?: "email" | "text";
}

/**
 * Inline-editable chip list.  Click pencil → enter edit mode; type
 * value + Enter or click + to add; click ✕ on a chip to remove.  Save
 * fires the handler with the canonical array; cancel reverts.  We
 * stage edits in local draft state so partial edits don't fire one
 * mutation per chip toggle — the save is atomic on commit.
 */
export function EditableChips({
  value,
  onSave,
  isPending,
  placeholder,
  label,
  emptyText = "—",
  lowercase = false,
  inputMode = "text",
}: EditableChipsProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<string[]>(value ?? []);
  const [newChip, setNewChip] = useState("");

  // Mirror the React docs' "adjusting state when prop changes" pattern
  // so the draft resets after a successful save (parent re-fetches and
  // ``value`` updates) without reaching for ``useEffect``.  See the
  // editor pattern note in PR #75.
  const [previousValue, setPreviousValue] = useState<string[] | null | undefined>(value);
  if (previousValue !== value) {
    setPreviousValue(value);
    setDraft(value ?? []);
  }

  const addChip = () => {
    let v = newChip.trim();
    if (!v) return;
    if (lowercase) v = v.toLowerCase();
    if (draft.includes(v)) {
      setNewChip("");
      return;
    }
    setDraft([...draft, v]);
    setNewChip("");
  };

  const removeChip = (chip: string) => {
    setDraft(draft.filter((c) => c !== chip));
  };

  const handleSave = () => {
    onSave(draft);
    setEditing(false);
  };

  const handleCancel = () => {
    setDraft(value ?? []);
    setNewChip("");
    setEditing(false);
  };

  return (
    <div className="space-y-1">
      {label && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{label}</span>
          {!editing && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 -mr-2"
              onClick={() => setEditing(true)}
            >
              <Pencil className="h-3 w-3" />
            </Button>
          )}
        </div>
      )}

      {editing ? (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1 min-h-[1.75rem]">
            {draft.map((chip) => (
              <Badge
                key={chip}
                variant="outline"
                className="font-mono text-xs gap-1"
              >
                {chip}
                <button
                  type="button"
                  onClick={() => removeChip(chip)}
                  className="hover:text-destructive"
                  aria-label={`Remove ${chip}`}
                >
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
          </div>
          <div className="flex gap-2">
            <Input
              value={newChip}
              onChange={(e) => setNewChip(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addChip();
                } else if (e.key === "Escape") {
                  handleCancel();
                }
              }}
              placeholder={placeholder}
              inputMode={inputMode}
              className="font-mono text-sm"
            />
            <Button size="sm" variant="ghost" onClick={addChip}>
              <Plus className="h-4 w-4" />
            </Button>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              className="h-7"
              onClick={handleSave}
              disabled={isPending}
            >
              {isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7"
              onClick={handleCancel}
            >
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <div
          className="flex flex-wrap gap-1 min-h-[1.5rem] items-center cursor-pointer group"
          onClick={() => setEditing(true)}
        >
          {(value ?? []).map((v) => (
            <Badge key={v} variant="outline" className="font-mono text-xs">
              {v}
            </Badge>
          ))}
          {(!value || value.length === 0) && (
            <span className="text-xs text-muted-foreground italic">
              {emptyText}
            </span>
          )}
          <Pencil className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity ml-1" />
        </div>
      )}
    </div>
  );
}
