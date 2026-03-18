import React, { useRef, useEffect, useMemo } from 'react';
import * as d3 from 'd3';

export default function NetworkGraph({ scanResult, dataset }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const topology = useMemo(() => genTopology(dataset), [dataset]);
  const involved = scanResult?.involved_sensors || [];

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const w = containerRef.current.clientWidth;
    const h = containerRef.current.clientHeight;
    if (w === 0 || h === 0) return;

    d3.select(svgRef.current).selectAll('*').remove();
    const svg = d3.select(svgRef.current).attr('width', w).attr('height', h);

    // Monochrome: segments differ by opacity, not color
    const opacityScale = d3.scaleOrdinal()
      .domain(topology.segments)
      .range([0.9, 0.65, 0.45, 0.3]);

    const sim = d3.forceSimulation(topology.nodes)
      .force('link', d3.forceLink(topology.links).id(d => d.id).distance(60))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(w / 2, h / 2))
      .force('collision', d3.forceCollide().radius(20));

    const link = svg.append('g')
      .selectAll('line')
      .data(topology.links)
      .join('line')
      .attr('stroke', '#222228')
      .attr('stroke-width', 1);

    const node = svg.append('g')
      .selectAll('circle')
      .data(topology.nodes)
      .join('circle')
      .attr('r', d => d.isRouter ? 10 : 6)
      .attr('fill', d => {
        if (involved.includes(d.id)) return '#4c8dff';
        return `rgba(142, 142, 150, ${opacityScale(d.segment)})`;
      })
      .attr('stroke', d => involved.includes(d.id) ? 'rgba(76, 141, 255, 0.4)' : 'none')
      .attr('stroke-width', d => involved.includes(d.id) ? 3 : 0)
      .style('cursor', 'grab')
      .call(drag(sim));

    const label = svg.append('g')
      .selectAll('text')
      .data(topology.nodes)
      .join('text')
      .text(d => d.label)
      .attr('font-size', 9)
      .attr('fill', d => involved.includes(d.id) ? '#4c8dff' : '#58585f')
      .attr('font-family', "'JetBrains Mono', monospace")
      .attr('dx', 12)
      .attr('dy', 3);

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
      label.attr('x', d => d.x).attr('y', d => d.y);
    });

    return () => sim.stop();
  }, [topology, involved]);

  function drag(sim) {
    return d3.drag()
      .on('start', (e, d) => {
        if (!e.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end', (e, d) => {
        if (!e.active) sim.alphaTarget(0);
        d.fx = null; d.fy = null;
      });
  }

  return (
    <div ref={containerRef} className="graph-container">
      <svg ref={svgRef} style={{ width: '100%', height: '100%' }} />
    </div>
  );
}

function genTopology(ds) {
  if (['swat', 'batadal', 'hai'].includes(ds)) {
    const nodes = [
      { id: 'FIT101', label: 'FIT101', segment: 'plc', isRouter: false },
      { id: 'LIT101', label: 'LIT101', segment: 'plc', isRouter: false },
      { id: 'MV101', label: 'MV101', segment: 'plc', isRouter: false },
      { id: 'P101', label: 'P101', segment: 'plc', isRouter: false },
      { id: 'P102', label: 'P102', segment: 'plc', isRouter: false },
      { id: 'AIT201', label: 'AIT201', segment: 'plc', isRouter: false },
      { id: 'HMI01', label: 'HMI', segment: 'scada', isRouter: false },
      { id: 'HIST01', label: 'Historian', segment: 'scada', isRouter: false },
      { id: 'SW1', label: 'SW-PLC', segment: 'infra', isRouter: true },
      { id: 'SW2', label: 'SW-SCADA', segment: 'infra', isRouter: true },
      { id: 'FW1', label: 'Firewall', segment: 'infra', isRouter: true },
      { id: 'WS01', label: 'WS-Eng1', segment: 'workstation', isRouter: false },
      { id: 'WS02', label: 'WS-Eng2', segment: 'workstation', isRouter: false },
    ];
    const links = [
      { source: 'FIT101', target: 'SW1' }, { source: 'LIT101', target: 'SW1' },
      { source: 'MV101', target: 'SW1' }, { source: 'P101', target: 'SW1' },
      { source: 'P102', target: 'SW1' }, { source: 'AIT201', target: 'SW1' },
      { source: 'HMI01', target: 'SW2' }, { source: 'HIST01', target: 'SW2' },
      { source: 'SW1', target: 'FW1' }, { source: 'SW2', target: 'FW1' },
      { source: 'WS01', target: 'FW1' }, { source: 'WS02', target: 'FW1' },
    ];
    return { nodes, links, segments: ['plc', 'scada', 'infra', 'workstation'] };
  }

  // IT network topology
  const nodes = [];
  for (let i = 0; i < 8; i++) {
    nodes.push({ id: `H${i + 1}`, label: `Host${i + 1}`, segment: 'internal', isRouter: false });
  }
  for (let i = 0; i < 3; i++) {
    nodes.push({ id: `S${i + 1}`, label: `Server${i + 1}`, segment: 'servers', isRouter: false });
  }
  nodes.push(
    { id: 'RTR', label: 'Router', segment: 'infra', isRouter: true },
    { id: 'FW', label: 'Firewall', segment: 'infra', isRouter: true },
  );

  const links = [];
  for (let i = 0; i < 8; i++) links.push({ source: `H${i + 1}`, target: 'RTR' });
  for (let i = 0; i < 3; i++) links.push({ source: `S${i + 1}`, target: 'FW' });
  links.push({ source: 'RTR', target: 'FW' });

  return { nodes, links, segments: ['internal', 'servers', 'infra'] };
}