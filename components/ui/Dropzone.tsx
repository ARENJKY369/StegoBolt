'use client';

import { UploadCloud } from 'lucide-react';
import { useRef, useState, type ReactNode } from 'react';

/**
 * Drag & drop file zone shared by Hide / Extract / Scan / Clean panels.
 * Files never leave the tab — the handle is passed straight to the caller's
 * client-side pipeline.
 */
export function FileDropzone({
  accept,
  hint,
  id,
  filled,
  onFile,
  children,
}: {
  accept: string;
  hint?: string;
  id?: string;
  filled: boolean;
  onFile: (file: File) => void;
  children?: ReactNode;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  const take = (files: FileList | null) => {
    if (files && files[0]) onFile(files[0]);
  };

  return (
    <div
      id={id}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        take(e.dataTransfer.files);
      }}
      onClick={() => !filled && inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && !filled) {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      className={`min-h-[64px] rounded-xl border border-dashed transition-colors ${
        over ? 'border-brand bg-brand/5' : filled ? 'border-hair2 bg-panel2/40' : 'cursor-pointer border-hair2 hover:border-brand/50 hover:bg-panel2/40'
      }`}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => {
          take(e.target.files);
          e.target.value = '';
        }}
      />
      {filled ? (
        <div className="p-3">{children}</div>
      ) : (
        <div className="flex flex-col items-center gap-1.5 px-4 py-7 text-center">
          <UploadCloud size={22} className="text-slate-500" />
          <p className="text-[13px] font-medium text-slate-300">
            Drag &amp; drop your file here, or <span className="text-emerald-400">click to browse</span>
          </p>
          <p className="text-[11px] text-slate-500">{hint ?? 'Processed 100% locally — the file never leaves this tab'}</p>
        </div>
      )}
    </div>
  );
}
