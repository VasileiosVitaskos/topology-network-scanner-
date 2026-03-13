import React, { useRef, useEffect, useMemo } from 'react';
import * as d3 from 'd3';

export default function NetworkGraph({ scanResult, dataset }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const topology = useMemo(() => buildTopology(dataset), [dataset]);

  // Get involved IPs from scan result
  const involved = useMemo(() => {
    const ips = new Set();
    if (scanResult?.involved_sensors) {
      (Array.isArray(scanResult.involved_sensors)
        ? scanResult.involved_sensors
        : []
      ).forEach(s => ips.add(s));
    }
    if (scanResult?.findings) {
      (Array.isArray(scanResult.findings)
        ? scanResult.findings
        : []
      ).forEach(f => {
        (f.involved_ips || []).forEach(ip => ips.add(ip));
      });
    }
    return ips;
  }, [scanResult]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;
    const w = containerRef.current.clientWidth;
    const h = containerRef.current.clientHeight;
    if (w === 0 || h === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', w).attr('height', h);

    // Background grid
    const defs = svg.append('defs');
    defs.append('pattern')
      .attr('id', 'grid')
      .attr('width', 40).attr('height', 40)
      .attr('patternUnits', 'userSpaceOnUse')
      .append('path')
      .attr('d', 'M 40 0 L 0 0 0 40')
      .attr('fill', 'none')
      .attr('stroke', '#151821')
      .attr('stroke-width', 0.5);

    svg.append('rect')
      .attr('width', w).attr('height', h)
      .attr('fill', 'url(#grid)');

    // Color by segment
    const segColors = {
      plc: '#00e5ff',
      scada: '#bb86fc',
      infra: '#80868b',
      workstation: '#00e676',
      dmz: '#ffab00',
      internal: '#00e676',
      servers: '#bb86fc',
    };

    // Simulation
    const sim = d3.forceSimulation(topology.nodes)
      .force('link', d3.forceLink(topology.links).id(d => d.id).distance(70))
      .force('charge', d3.forceManyBody().strength(-150))
      .force('center', d3.forceCenter(w / 2, h / 2))
      .force('collision', d3.forceCollide().radius(24));

    // Links
    const link = svg.append('g')
      .selectAll('line')
      .data(topology.links)
      .join('line')
      .attr('stroke', '#1e2330')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.6);

    // Nodes
    const nodeGroup = svg.append('g')
      .selectAll('g')
      .data(topology.nodes)
      .join('g')
      .call(drag(sim));

    // Node circles
    nodeGroup.append('circle')
      .attr('r', d => d.isRouter ? 12 : 8)
      .attr('fill', d => {
        if (involved.has(d.id) || involved.has(d.ip)) return '#ff1744';
        return segColors[d.segment] || '#80868b';
      })
      .attr('stroke', d => {
        if (involved.has(d.id) || involved.has(d.ip)) return '#ff174480';
        return 'transparent';
      })
      .attr('stroke-width', d => (involved.has(d.id) || involved.has(d.ip)) ? 4 : 0)
      .attr('opacity', 0.9);

    // Pulsing animation for involved nodes
    nodeGroup.filter(d => involved.has(d.id) || involved.has(d.ip))
      .append('circle')
      .attr('r', 16)
      .attr('fill', 'none')
      .attr('stroke', '#ff1744')
      .attr('stroke-width', 2)
      .attr('opacity', 0)
      .append('animate')
      .attr('attributeName', 'r')
      .attr('from', 10).attr('to', 24)
      .attr('dur', '1.5s')
      .attr('repeatCount', 'indefinite');

    // Labels
    nodeGroup.append('text')
      .text(d => d.label)
      .attr('font-size', 9)
      .attr('font-family', "'JetBrains Mono', monospace")
      .attr('fill', d => (involved.has(d.id) || involved.has(d.ip)) ? '#ff1744' : '#5f6368')
      .attr('dx', 14)
      .attr('dy', 3);

    // Tick
    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeGroup.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Segment labels
    const segments = [...new Set(topology.nodes.map(n => n.segment))];
    svg.append('g')
      .selectAll('text')
      .data(segments)
      .join('text')
      .text(d => d.toUpperCase().replace('_', ' '))
      .attr('x', 16)
      .attr('y', (_, i) => 20 + i * 16)
      .attr('font-size', 9)
      .attr('font-family', "'JetBrains Mono', monospace")
      .attr('fill', d => segColors[d] || '#5f6368')
      .attr('opacity', 0.5);

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
    <div ref={containerRef} style={{ width: '100%', height: '100%', position: 'relative' }}>
      <svg ref={svgRef} style={{ width: '100%', height: '100%' }} />
      {!scanResult && (
        <div className="empty-state" style={{
          position: 'absolute', inset: 0,
          pointerEvents: 'none'
        }}>
          <div className="empty-icon">⬡</div>
          <div className="empty-text">
            Run a scan to begin analysis<br />
            Quick Scan = AI log analysis<br />
            Deep Scan = Topological detection
          </div>
        </div>
      )}
    </div>
  );
}

function buildTopology(ds) {
  if (['swat', 'batadal', 'hai', 'live'].includes(ds)) {
    const nodes = [
      { id: 'PLC-S1', ip: '192.168.1.10', label: 'PLC-Stage1', segment: 'plc', isRouter: false },
      { id: 'PLC-S2', ip: '192.168.1.11', label: 'PLC-Stage2', segment: 'plc', isRouter: false },
      { id: 'PLC-S3', ip: '192.168.1.12', label: 'PLC-Stage3', segment: 'plc', isRouter: false },
      { id: 'PLC-S4', ip: '192.168.1.13', label: 'PLC-Stage4', segment: 'plc', isRouter: false },
      { id: 'HMI', ip: '192.168.2.20', label: 'HMI-Main', segment: 'scada', isRouter: false },
      { id: 'HIST', ip: '192.168.2.21', label: 'Historian', segment: 'scada', isRouter: false },
      { id: 'SW-PLC', label: 'SW-PLC', segment: 'infra', isRouter: true },
      { id: 'SW-SCADA', label: 'SW-SCADA', segment: 'infra', isRouter: true },
      { id: 'FW', label: 'Firewall', segment: 'infra', isRouter: true },
      { id: 'WS1', ip: '192.168.3.50', label: 'WS-Eng1', segment: 'workstation', isRouter: false },
      { id: 'WS2', ip: '192.168.3.51', label: 'WS-Eng2', segment: 'workstation', isRouter: false },
      { id: 'WS3', ip: '192.168.3.52', label: 'WS-Ops1', segment: 'workstation', isRouter: false },
      { id: 'DMZ1', ip: '10.0.0.5', label: 'FW-Ext', segment: 'dmz', isRouter: false },
      { id: 'DMZ2', ip: '10.0.0.6', label: 'DNS-Pub', segment: 'dmz', isRouter: false },
    ];
    const links = [
      { source: 'PLC-S1', target: 'SW-PLC' },
      { source: 'PLC-S2', target: 'SW-PLC' },
      { source: 'PLC-S3', target: 'SW-PLC' },
      { source: 'PLC-S4', target: 'SW-PLC' },
      { source: 'HMI', target: 'SW-SCADA' },
      { source: 'HIST', target: 'SW-SCADA' },
      { source: 'SW-PLC', target: 'FW' },
      { source: 'SW-SCADA', target: 'FW' },
      { source: 'WS1', target: 'FW' },
      { source: 'WS2', target: 'FW' },
      { source: 'WS3', target: 'FW' },
      { source: 'DMZ1', target: 'FW' },
      { source: 'DMZ2', target: 'FW' },
    ];
    return { nodes, links };
  }

  // Generic fallback
  const nodes = [...Array(6)].map((_, i) => ({
    id: `H${i}`, label: `Host${i}`, segment: 'internal', isRouter: false
  }));
  nodes.push({ id: 'RTR', label: 'Router', segment: 'infra', isRouter: true });
  const links = nodes.filter(n => !n.isRouter).map(n => ({ source: n.id, target: 'RTR' }));
  return { nodes, links };
}
