import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { CredentialSummary } from '../lib/credentials';

function AccessBadge({ shared }: { shared: boolean }) {
  return (
    <span
      className={`inline-flex items-center justify-center px-1.5 py-0.5 rounded text-[10px] font-semibold whitespace-nowrap ${
        shared ? 'bg-accent/15 text-accent' : 'bg-surface-hover text-text-secondary'
      }`}
    >
      {shared ? 'Shared' : 'Personal'}
    </span>
  );
}

interface CredentialPickerProps {
  /** Credentials allowed for this connection's protocol and sharing state. */
  pickableCreds: CredentialSummary[];
  /** The linked credential, even if no longer pickable here (unshared/wrong type) — null if none or deleted. */
  selectedCred: CredentialSummary | null;
  /** Selected credential id, or '' for manual entry. */
  value: string;
  onChange: (id: string) => void;
}

/**
 * Dropdown for picking "Enter manually" or a saved credential. Renders as a
 * table (Personal/Shared, name, username) since a native <select> can't show
 * colored badges or columns.
 */
export function CredentialPicker({ pickableCreds, selectedCred, value, onChange }: CredentialPickerProps) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const anchorRef = useRef<HTMLDivElement>(null);
  const dropRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number; width: number }>({ top: 0, left: 0, width: 320 });

  const unavailable = !!value && !selectedCred;
  const notAllowed = !!selectedCred && !pickableCreds.some((c) => c.id === selectedCred.id);

  useEffect(() => {
    if (!open || !anchorRef.current) return;
    const rect = anchorRef.current.getBoundingClientRect();
    const dropH = 320;
    const spaceBelow = window.innerHeight - rect.bottom - 8;
    const top = spaceBelow >= dropH ? rect.bottom + 4 : Math.max(8, rect.top - dropH - 4);
    setPos({ top, left: rect.left, width: rect.width });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function handle(e: MouseEvent) {
      if (anchorRef.current?.contains(e.target as Node) || dropRef.current?.contains(e.target as Node)) return;
      setOpen(false);
    }
    // Capture phase: parent modals call stopPropagation() on mousedown (bubble phase),
    // which would otherwise stop this from ever reaching document and prevent closing.
    document.addEventListener('mousedown', handle, true);
    return () => document.removeEventListener('mousedown', handle, true);
  }, [open]);

  useEffect(() => {
    if (open) searchRef.current?.focus();
    else setSearch('');
  }, [open]);

  const q = search.trim().toLowerCase();
  const filtered = q
    ? pickableCreds.filter((c) => c.name.toLowerCase().includes(q) || (c.username ?? '').toLowerCase().includes(q))
    : pickableCreds;
  const rows = [...filtered]
    .sort((a, b) => a.name.localeCompare(b.name))
    .sort((a, b) => Number(a.shared) - Number(b.shared)); // stable: personal first, each still name-sorted

  function pick(id: string) {
    onChange(id);
    setOpen(false);
  }

  return (
    <div ref={anchorRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`w-full flex items-center gap-2 px-2.5 py-1.5 bg-surface border rounded text-sm text-left transition-colors ${
          open ? 'border-accent ring-1 ring-accent/30' : 'border-border hover:border-text-secondary/30'
        }`}
      >
        {value && selectedCred ? (
          <>
            <AccessBadge shared={selectedCred.shared} />
            <span className="flex-1 min-w-0 truncate text-text-primary font-medium">{selectedCred.name}</span>
            {selectedCred.username && (
              <span className="shrink-0 text-text-secondary font-mono text-xs truncate max-w-[35%]">{selectedCred.username}</span>
            )}
            {notAllowed && <span className="shrink-0 text-[10px] text-red-400">not allowed here</span>}
          </>
        ) : unavailable ? (
          <span className="flex-1 text-red-400">(unavailable credential)</span>
        ) : (
          <span className="flex-1 text-text-secondary">Enter manually</span>
        )}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-text-secondary/60 shrink-0">
          <polyline points={open ? '18 15 12 9 6 15' : '6 9 12 15 18 9'} />
        </svg>
      </button>

      {open && createPortal(
        <div
          ref={dropRef}
          className="fixed z-[9999] rounded-lg border border-border bg-surface shadow-2xl overflow-hidden flex flex-col"
          style={{ top: pos.top, left: pos.left, width: pos.width }}
        >
          <div className="p-2 border-b border-border/60 shrink-0">
            <input
              ref={searchRef}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Escape') setOpen(false); }}
              placeholder="Search credentials…"
              className="w-full px-2 py-1 bg-surface-alt border border-border rounded text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
            />
          </div>

          <button
            type="button"
            onClick={() => pick('')}
            className={`w-full flex items-center px-3 py-2 text-xs text-left border-b border-border/60 transition-colors shrink-0 ${
              !value ? 'bg-accent/5 text-accent font-medium' : 'text-text-primary hover:bg-surface-hover'
            }`}
          >
            Enter manually
          </button>

          {rows.length > 0 && (
            <div className="grid grid-cols-[76px_1fr_minmax(0,120px)] gap-2 px-3 py-1.5 text-[10px] font-semibold text-text-secondary/60 uppercase tracking-wider border-b border-border/60 shrink-0">
              <span>Access</span>
              <span>Name</span>
              <span>Username</span>
            </div>
          )}

          <div className="max-h-[240px] overflow-y-auto overscroll-contain py-1">
            {rows.length === 0 ? (
              <p className="px-3 py-4 text-xs text-text-secondary text-center">
                {q ? `No credentials matching "${search}"` : 'No saved credentials for this connection type.'}
              </p>
            ) : (
              rows.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => pick(c.id)}
                  className={`w-full grid grid-cols-[76px_1fr_minmax(0,120px)] items-center gap-2 px-3 py-2 text-xs text-left transition-colors ${
                    value === c.id ? 'bg-accent/5' : 'hover:bg-surface-hover'
                  }`}
                >
                  <span><AccessBadge shared={c.shared} /></span>
                  <span className={`truncate ${value === c.id ? 'text-accent font-medium' : 'text-text-primary'}`}>{c.name}</span>
                  <span className="text-text-secondary font-mono truncate">{c.username || '—'}</span>
                </button>
              ))
            )}
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
}
