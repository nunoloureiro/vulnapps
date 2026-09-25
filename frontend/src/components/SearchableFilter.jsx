import { useEffect, useId, useRef, useState } from 'react';
import './SearchableFilter.css';

export function SearchableFilter({ label, value, options, onChange, placeholder = 'All', multiple = false }) {
  const id = useId();
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const selectedValues = multiple ? (Array.isArray(value) ? value : []) : [];
  const selected = options.find((option) => String(option.value) === String(value));
  const hasValue = multiple ? selectedValues.length > 0 : value !== '' && value != null;
  const matches = options.filter((option) => String(option.label).toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));
  const items = [{ value: '', label: placeholder }, ...matches];
  const currentIndex = Math.min(activeIndex, items.length - 1);

  useEffect(() => {
    if (open) listRef.current?.children[currentIndex]?.scrollIntoView({ block: 'nearest' });
  }, [open, currentIndex, query]);

  function close() {
    setOpen(false);
    setQuery('');
  }

  function choose(option) {
    if (multiple) {
      if (option.value === '') {
        onChange([]);
        setQuery('');
        setActiveIndex(0);
      } else if (isSelected(option)) {
        onChange(selectedValues.filter((item) => String(item) !== String(option.value)));
      } else {
        onChange([...selectedValues, option.value]);
      }
      return;
    }
    onChange(option.value);
    close();
  }

  function isSelected(option) {
    if (multiple) return option.value === '' ? !hasValue : selectedValues.some((item) => String(item) === String(option.value));
    return String(option.value) === String(value ?? '');
  }

  function show() {
    setOpen(true);
    setActiveIndex(multiple ? 0 : Math.max(0, items.findIndex(isSelected)));
  }

  function handleKeyDown(event) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!open) {
        show();
      } else {
        const direction = event.key === 'ArrowDown' ? 1 : -1;
        setActiveIndex((currentIndex + direction + items.length) % items.length);
      }
    } else if (event.key === 'Enter' && open) {
      event.preventDefault();
      choose(items[currentIndex]);
    } else if (event.key === 'Escape' && open) {
      event.preventDefault();
      event.stopPropagation();
      close();
    }
  }

  return (
    <div className="searchable-filter" onBlur={(event) => {
      if (!event.currentTarget.contains(event.relatedTarget)) close();
    }}>
      <label className="searchable-filter-label" htmlFor={id}>{label}</label>
      <div className={`searchable-filter-control${open ? ' is-open' : ''}`}>
        <input
          ref={inputRef}
          id={id}
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={open}
          aria-controls={`${id}-list`}
          aria-activedescendant={open ? `${id}-option-${currentIndex}` : undefined}
          autoComplete="off"
          placeholder={open || (multiple && hasValue) ? `Search ${label.toLocaleLowerCase()}…` : placeholder}
          value={open || multiple ? query : (hasValue ? selected?.label ?? String(value) : '')}
          onFocus={show}
          onClick={() => { if (!open) show(); }}
          onChange={(event) => {
            const nextQuery = event.target.value;
            setQuery(nextQuery);
            setOpen(true);
            setActiveIndex(nextQuery.trim() ? 1 : 0);
          }}
          onKeyDown={handleKeyDown}
        />
        {hasValue && (
          <button
            type="button"
            className="searchable-filter-clear"
            aria-label={`Clear ${label.toLocaleLowerCase()} filter`}
            onMouseDown={(event) => event.preventDefault()}
            onClick={() => {
              inputRef.current?.focus();
              choose({ value: '' });
            }}
          >×</button>
        )}
        <span className="searchable-filter-chevron" aria-hidden="true">⌄</span>
      </div>
      {multiple && hasValue && (
        <ul className="searchable-filter-chips" aria-label={`Selected ${label.toLocaleLowerCase()}`}>
          {selectedValues.map((selectedValue) => {
            const selectedLabel = options.find((option) => String(option.value) === String(selectedValue))?.label ?? String(selectedValue);
            return (
              <li key={selectedValue}>
                <span>{selectedLabel}</span>
                <button
                  type="button"
                  aria-label={`Remove ${selectedLabel}`}
                  onClick={() => {
                    inputRef.current?.focus();
                    choose({ value: selectedValue });
                  }}
                >×</button>
              </li>
            );
          })}
        </ul>
      )}
      {open && (
        <div className="searchable-filter-menu">
          {hasValue && !multiple && <div className="searchable-filter-selection">Selected: {selected?.label ?? String(value)}</div>}
          <ul ref={listRef} id={`${id}-list`} role="listbox" aria-label={label} aria-multiselectable={multiple || undefined}>
            {items.map((option, index) => (
              <li
                key={option.value}
                id={`${id}-option-${index}`}
                role="option"
                aria-selected={isSelected(option)}
                className={index === currentIndex ? 'is-active' : ''}
                onMouseDown={(event) => event.preventDefault()}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => choose(option)}
              >
                <span>{option.label}</span>
                {isSelected(option) && <span aria-hidden="true">✓</span>}
              </li>
            ))}
          </ul>
          {matches.length === 0 && <div className="searchable-filter-empty" role="status">No matches found</div>}
        </div>
      )}
    </div>
  );
}
