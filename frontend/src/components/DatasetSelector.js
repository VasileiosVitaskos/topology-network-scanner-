import React from 'react';

const DATASETS = [
  { value: 'hai', label: 'HAI (Industrial)' },
  { value: 'swat', label: 'SWaT (Water)' },
  { value: 'batadal', label: 'BATADAL (Water)' },
  { value: 'live', label: 'Live / Simulation' },
];

export default function DatasetSelector({ value, onChange }) {
  return (
    <select className="dataset-select" value={value} onChange={e => onChange(e.target.value)}>
      {DATASETS.map(d => (
        <option key={d.value} value={d.value}>{d.label}</option>
      ))}
    </select>
  );
}