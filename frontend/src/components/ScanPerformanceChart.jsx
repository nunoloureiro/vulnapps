import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { SearchableFilter } from './SearchableFilter';
import { chartMetrics, chartResources, chartObservations, scannerColor, formatChartResource } from '../utils/scanChart';

const H = 380, top = 38, bottom = 65;
const pct = value => value === null ? 'Unavailable' : `${(value * 100).toFixed(1)}%`;
const types = { blackbox: 'Blackbox', greybox: 'Greybox', whitebox: 'Whitebox', unknown: 'Unknown type' };
const runName = scan => `#${scan.id} · ${scan.app_name || 'Unknown app'}${scan.app_version ? ` ${scan.app_version}` : ''} · ${scan.scanner_version || 'Version unknown'}`;

function Marker({ type, x, y, radius, color }) {
  const common = { fill: type === 'greybox' ? 'var(--bg-panel)' : color, stroke: color, strokeWidth: 2 };
  if (type === 'whitebox') return <polygon points={`${x},${y - radius * 1.2} ${x + radius},${y + radius} ${x - radius},${y + radius}`} {...common} />;
  if (type === 'unknown') return <polygon points={`${x},${y - radius} ${x + radius},${y} ${x},${y + radius} ${x - radius},${y}`} {...common} />;
  return <circle cx={x} cy={y} r={radius} {...common} />;
}

export function ScanPerformanceChart({ scans, labelsMap = {}, resource = 'cost', metric = 'weighted_f05', onAxisChange, latest }) {
  const [params] = useSearchParams();
  const view = params.get('chart_plot') === 'pr' ? 'pr' : 'quality';
  const grouped = params.get('chart_group') !== 'runs';
  const weight = ['plain', 'weighted', 'shift'].includes(params.get('chart_weight')) ? params.get('chart_weight') : 'plain';
  const splitLabels = params.getAll('chart_label');
  const [selectedId, setSelectedId] = useState(null);
  const [hoveredId, setHoveredId] = useState(null);
  const plotRef = useRef(null);
  const [width, setWidth] = useState(1100);
  const arrowId = useId().replaceAll(':', '');
  const optionsKey = JSON.stringify([view, resource, metric, weight, grouped, splitLabels]);
  const { points, excluded, missingResource, missingScore } = useMemo(
    () => chartObservations(scans, labelsMap, { view, resource, metric, weight, grouped, splitLabels }),
    [scans, labelsMap, optionsKey]);
  const W = Math.max(280, width), left = W < 500 ? 48 : 74, right = W < 500 ? 16 : 32;
  useEffect(() => {
    if (!plotRef.current) return;
    const observer = new ResizeObserver(entries => setWidth(entries[0].contentRect.width));
    observer.observe(plotRef.current);
    return () => observer.disconnect();
  }, [points.length > 0]);
  const labels = [...new Set([...Object.values(labelsMap).flat().map(label => label.name), ...splitLabels])].sort();
  const active = points.find(point => point.id === (hoveredId ?? selectedId));
  const selected = points.find(point => point.id === selectedId);
  const plotted = points.reduce((n, point) => n + point.scans.length, 0);
  const scanners = [...new Set(points.map(point => point.scanner))].sort();
  const extent = Math.max(...points.map(point => point.x), 0) * 1.08 || 1;
  const magnitude = 10 ** Math.floor(Math.log10(extent / 4));
  const step = [1, 2, 5, 10].find(value => value * magnitude >= extent / 4) * magnitude;
  const maxX = view === 'pr' ? 1 : step * 4;
  const inset = 16;
  const px = value => left + inset + value / maxX * (W - left - right - 2 * inset);
  const py = value => H - bottom - inset - value * (H - top - bottom - 2 * inset);
  const costs = points.map(point => point.cost).filter(value => value > 0);
  const minCost = costs.length ? Math.min(...costs) : null;
  const maxCost = costs.length ? Math.max(...costs) : null;
  const pointColor = point => {
    if (view === 'quality') return scannerColor(point.scanner);
    if (point.cost === null) return 'var(--text-secondary)';
    const fraction = point.cost <= 0 || minCost === maxCost ? 0 : Math.max(0, Math.min(1, Math.log(point.cost / minCost) / Math.log(maxCost / minCost)));
    return `hsl(${210 - fraction * 185} 75% 60%)`;
  };
  const xLabel = view === 'pr' ? `${weight === 'plain' ? 'Catalog' : 'Weighted'} recall` : chartResources[resource];
  const yLabel = view === 'pr' ? `${weight === 'plain' ? 'Conservative' : 'Weighted'} precision` : chartMetrics[metric];
  const xValue = value => view === 'pr' ? pct(value) : formatChartResource(value, resource);
  const tooltipWidth = Math.min(300, W - 16);
  const mixedApps = new Set(points.flatMap(point => point.scans.map(scan => scan.app_id))).size > 1;
  const reviewed = view === 'pr' ? weight !== 'plain' : ['weighted_f05', 'weighted_precision'].includes(metric);
  const awaitingReview = reviewed ? scans.filter(scan => scan.metrics?.weighted_score_provisional !== false).length : 0;
  const pp = value => `${(value * 100).toFixed(1)} pp`;
  const stats = (summary, format, spread = format) => summary.n > 1
    ? `SD ${spread(summary.std)} · Range ${format(summary.min)}–${format(summary.max)}` : 'SD unavailable for one run';

  return <section className="card scan-chart" aria-label="Run performance chart">
    <div className="scan-chart-header">
      <div><h2>Performance chart</h2><p className="text-muted">{grouped ? 'Scanner + scan type' : 'One point per run'}{grouped && splitLabels.length ? ' + chosen variations' : ''} · Better toward the {view === 'pr' ? 'upper right' : 'upper left'}</p></div>
      <div className="scan-chart-switch" role="group" aria-label="Chart view">
        <button aria-pressed={view === 'quality'} onClick={() => onAxisChange('chart_plot', 'quality')}>Quality vs. resources</button>
        <button aria-pressed={view === 'pr'} onClick={() => onAxisChange('chart_plot', 'pr')}>Precision vs. recall</button>
      </div>
    </div>
    <div className="scan-chart-toolbar">
      <div className="scan-chart-controls">
        <label>Points represent<select className="form-select" value={grouped ? 'scanner' : 'runs'} onChange={e => onAxisChange('chart_group', e.target.value)}>
          <option value="scanner">Scanner + scan type</option><option value="runs">Individual runs</option>
        </select></label>
        {view === 'quality' ? <>
          <label>Y · Quality<select className="form-select" value={metric} onChange={e => onAxisChange('chart_y', e.target.value)}>
            {Object.entries(chartMetrics).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
          <label>X · Resources<select className="form-select" value={resource} onChange={e => onAxisChange('chart_x', e.target.value)}>
            {Object.entries(chartResources).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
        </> : <fieldset className="scan-chart-weighting"><legend>Severity weighting</legend><div>
          {[['plain', 'Unweighted'], ['shift', 'Shift'], ['weighted', 'Weighted']].map(([value, label]) => <label key={value}>
            <input type="radio" name={`weight-${arrowId}`} value={value} checked={weight === value} onChange={() => onAxisChange('chart_weight', value)} /><span>{label}</span>
          </label>)}
        </div></fieldset>}
        {grouped && <div className="scan-chart-variations"><SearchableFilter label="Grouping labels" multiple value={splitLabels}
          options={labels.map(label => ({ value: label, label }))} onChange={values => onAxisChange('chart_label', values)}
          placeholder="Choose model or harness labels…" allLabel="Blend all variations" /></div>}
      </div>
      {grouped && <p className="scan-chart-variation-help">{splitLabels.length
        ? 'Group on these labels; keep remaining runs as “Other variations”.'
        : 'Model and harness variations are blended. Choose grouping labels to separate them.'}</p>}
    </div>
    <div className="scan-chart-status"><p role="status">{plotted} / {scans.length} runs{grouped ? ` · ${points.length} groups` : ''}{latest ? ' · Latest per scanner and app' : ''}{mixedApps ? ' · Mixed app versions' : ''}</p>
      {excluded > 0 && <details><summary>{excluded} omitted</summary><p>{view === 'quality' ? `${missingResource} missing or restricted ${resource}; ` : ''}{missingScore} unavailable scores{awaitingReview ? `; ${awaitingReview} awaiting review` : ''}. Reasons can overlap.</p></details>}
    </div>
    {points.length ? <>
      <div className="scan-chart-legend">
        {[...new Set(points.map(point => point.type))].sort().map(type => <span key={type}><svg width="20" height="20" aria-hidden="true"><Marker type={type} x={10} y={10} radius={5} color="var(--text-secondary)" /></svg>{types[type]}</span>)}
        {grouped && <span>Marker size grows with run count</span>}
        {view === 'quality' ? scanners.map(scanner => <span key={scanner}><i style={{ background: scannerColor(scanner) }} />{scanner}</span>)
          : <><span>Cost: {minCost === null ? costs.length === 0 && points.some(point => point.cost === 0) ? '$0' : 'unavailable' : minCost === maxCost ? formatChartResource(minCost, 'cost') : <>{formatChartResource(minCost, 'cost')}<i className="scan-chart-cost-scale" />{formatChartResource(maxCost, 'cost')} · log scale</>}</span><span>Gray = cost unavailable · $0 uses low-cost color</span></>}
      </div>
      {view === 'pr' && weight === 'shift' && <p className="scan-chart-shift-key">Small hollow dot: unweighted · Arrow → scan-type marker: weighted</p>}
      <div className="scan-chart-plot" ref={plotRef}>
        <svg viewBox={`0 0 ${W} ${H}`} role="group" aria-label={`${yLabel} versus ${xLabel}. Select a point or use the inspector.`}>
          <defs><marker id={arrowId} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke" /></marker></defs>
          {(W < 500 ? [0, .5, 1] : [0, .25, .5, .75, 1]).map(value => <g key={value}>
            <line x1={left} x2={W - right} y1={py(value)} y2={py(value)} className="scan-chart-grid" />
            <text x={left - 12} y={py(value) + 4} textAnchor="end">{Math.round(value * 100)}%</text>
            <line x1={px(value * maxX)} x2={px(value * maxX)} y1={top} y2={H - bottom} className="scan-chart-grid" />
            <text x={px(value * maxX)} y={H - bottom + 25} textAnchor="middle">{xValue(value * maxX)}</text>
          </g>)}
          <text x={left} y={20} className="scan-chart-axis">{yLabel} (%) ↑</text>
          <text x={(W + left - right) / 2} y={H - 9} textAnchor="middle" className="scan-chart-axis">{xLabel}{view === 'pr' ? ' (%)' : ''} →</text>
          {points.map(point => {
            const color = pointColor(point), r = grouped ? Math.min(13, 4 + Math.sqrt(point.scans.length) * 2) : 6;
            const description = `${point.name}, ${yLabel} ${pct(point.y)}, ${xLabel} ${xValue(point.x)}, ${point.scans.length} runs, ${point.targetCount} targets`;
            const x = px(point.x), y = py(point.y);
            return <g key={point.id}>
              {view === 'pr' && weight === 'shift' && Math.hypot(x - px(point.plain.x), y - py(point.plain.y)) > r + 4 && <>
                <circle cx={px(point.plain.x)} cy={py(point.plain.y)} r="3" fill="var(--bg-panel)" stroke={color} />
                <line x1={px(point.plain.x)} y1={py(point.plain.y)} x2={x - Math.cos(Math.atan2(y - py(point.plain.y), x - px(point.plain.x))) * (r + 3)} y2={y - Math.sin(Math.atan2(y - py(point.plain.y), x - px(point.plain.x))) * (r + 3)} stroke={color} strokeWidth={active?.id === point.id ? 2.5 : 1.2} markerEnd={`url(#${arrowId})`} className="scan-chart-shift" />
              </>}
              <g className="scan-chart-point" tabIndex={0} role="button" aria-label={description} aria-pressed={selectedId === point.id}
                onMouseEnter={() => setHoveredId(point.id)} onMouseLeave={() => setHoveredId(null)} onFocus={() => setHoveredId(point.id)} onBlur={() => setHoveredId(null)}
                onClick={() => setSelectedId(point.id)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedId(point.id); } }}>
                <title>{description}</title><circle cx={x} cy={y} r={Math.max(16, r)} fill="transparent" />
                {active?.id === point.id && <circle cx={x} cy={y} r={r + 5} fill="none" stroke="var(--text)" strokeWidth="1" />}
                <Marker type={point.type} x={x} y={y} radius={r} color={color} />
              </g>
            </g>;
          })}
        </svg>
        {active && <div className="scan-chart-tooltip" aria-hidden="true" style={{ width: tooltipWidth,
          left: Math.max(8, Math.min(W - tooltipWidth - 8, px(active.x) + 14)), top: Math.max(36, Math.min(H - 105, py(active.y) - 78)) }}>
          <strong>{active.name}</strong><span>{yLabel}: {pct(active.y)}</span><span>{xLabel}: {xValue(active.x)} · n={active.scans.length}</span>
        </div>}
      </div>
      <div className="scan-chart-inspector">
        <label>Inspect {grouped ? 'a group' : 'a run'}<select className="form-select" value={selected?.id ?? ''} onChange={e => setSelectedId(e.target.value || null)}>
          <option value="">Select a point…</option>{points.map(point => <option key={point.id} value={point.id}>{point.name} · n={point.scans.length}</option>)}
        </select></label>
        <div className="scan-chart-run" aria-live="polite">{active ? <>
          <strong>{active.name}</strong><span>{yLabel}: {pct(active.y)} · {xLabel}: {xValue(active.x)}</span>
          {grouped && <><span className="text-muted">{yLabel}: {stats(active.yStats, pct, pp)}</span><span className="text-muted">{xLabel}: {stats(active.xStats, xValue, view === 'pr' ? pp : xValue)}</span></>}
          <span className="text-muted">{active.scans.length} runs · {active.targetCount} app versions · Mean cost: {active.cost === null ? 'unavailable (one or more runs)' : formatChartResource(active.cost, 'cost')}</span>
          {view === 'pr' && weight === 'shift' && <span>Unweighted {pct(active.plain.y)} precision / {pct(active.plain.x)} recall → weighted {pct(active.weighted.y)} / {pct(active.weighted.x)}</span>}
        </> : <span className="text-muted">Hover to preview; select a point for contributing runs and labels. Use the selector for overlapping points.</span>}</div>
      </div>
      {selected && <details className="scan-chart-contributors"><summary>Contributing runs ({selected.scans.length})</summary>
        <ul>{selected.scans.map(scan => <li key={scan.id}><Link to={`/scans/${scan.id}`}>{runName(scan)}</Link><span className="text-muted"> · {scan.scan_date || 'Date unavailable'} · {(labelsMap[scan.id] || []).map(label => label.name).join(' · ') || 'No labels'}</span></li>)}</ul>
      </details>}
    </> : <div className="scan-chart-empty"><h3>{awaitingReview === scans.length && scans.length ? 'Awaiting review' : 'No runs to plot'}</h3><p>{view === 'pr' ? 'Precision and recall require a scored catalog. Weighted and shift views also require completed finding and FP impact review. Cost is optional.' : 'Choose another metric or resource. Runs need a score and an accessible cost or duration.'}</p></div>}
    <p className="scan-summary-note">{view === 'pr' && weight === 'shift' ? 'Arrows show unweighted → weighted scores for the same runs. ' : ''}{mixedApps ? 'Mixed app versions: descriptive averages, not a matched comparison. ' : ''}{reviewed ? 'Reviewed weighted scores only. ' : ''}{grouped ? 'Counts show coverage, not confidence.' : ''}</p>
    <details className="scan-stat-help"><summary>Scoring and comparison limits</summary>
      <p>Each run has equal weight within its group; unselected model, harness and version variations are blended. Choose the same app version and setup for a matched comparison. Unknown cost stays visible in gray on precision/recall; missing cost or duration omits only that resource point. Shift uses only runs with both score variants, so switching weighting can change the available cohort.</p>
      <p>Scanner identifies the tool; labels describe model, harness and other variations. Scan type uses an explicit supported type, otherwise an unambiguous blackbox, greybox/graybox or whitebox label. Missing, conflicting or unsupported types remain unknown. Names and source-access labels never imply a type.</p>
      <p>Unweighted precision in the precision/recall view is TP / (TP + clustered FP + pending); recall is TP / (TP + FN). Pending findings count against precision. This conservative view differs from the pending-excluding precision selectable in quality versus resources.</p>
      <p>Weighted precision uses the canonical reviewed impact score. Weighted recall is credited / available impact, including vulnerability and chain credit; it is impact coverage, not an independent severity-weighted count of findings. Shift arrows connect unweighted to weighted means for the same contributing runs. Reviewer FP penalties use 1/3/9/27 impact points.</p>
      <p>Resource and score means use the same contributing runs. Hidden or missing cost is never zero, and a group's cost color is unknown if any contributing run lacks cost. Standard deviation is the sample spread of run scores, not a confidence interval or a measure of repeatability across different setups. Scores use the current benchmark revision. Compare the same application version, corpus and scan settings.</p>
    </details>
  </section>;
}
