import React from 'react';

const DS = [
  { value: 'swat', label: 'SWaT (Water)' },
  { value: 'batadal', label: 'BATADAL (Water)' },
  { value: 'hai', label: 'HAI (Industrial)' },
  { value: 'cicids', label: 'CICIDS (IT)' },
];

export default function DatasetSelector({ value, onChange }) {
  return (
    <select className="dataset-select" value={value} onChange={e => onChange(e.target.value)}>
      {DS.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
    </select>
  );
}
