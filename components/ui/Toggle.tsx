'use client';

/**
 * The ON/OFF switch from the reference UI: green pill, label at the far side
 * of the knob.
 */
export function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-[24px] w-[52px] shrink-0 items-center rounded-full transition-colors duration-200 disabled:cursor-not-allowed disabled:opacity-40 ${
        checked ? 'bg-[#22a35b]' : 'bg-[#2a3444]'
      }`}
    >
      <span
        className={`absolute text-[8px] font-extrabold tracking-wider ${
          checked ? 'left-1.5 text-white' : 'right-1.5 text-slate-500'
        }`}
      >
        {checked ? 'ON' : 'OFF'}
      </span>
      <span
        className={`inline-block h-[18px] w-[18px] rounded-full bg-white shadow transition-transform duration-200 ${
          checked ? 'translate-x-[31px]' : 'translate-x-[3px]'
        }`}
      />
    </button>
  );
}
