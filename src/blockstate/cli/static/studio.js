/**
 * Blockstate Studio Visual Statechart Controller
 * 1965 Archival Engineering & British Rail Mechanical Interlocking
 * Zero external libraries. Strict British English.
 */

(function () {
  'use strict';

  // Application State
  const state = {
    agentName: '',
    initialStage: '',
    stages: {},
    transitions: [],
    nodeLayout: {},
    selectedStage: null,
    precursorStage: null,
    targetStage: null,
    proofResult: null,
    traces: [],
    currentTraceIndex: 0,
    pan: { x: 80, y: 80 },
    zoom: 1.0,
    isPanning: false,
    startPan: { x: 0, y: 0 }
  };

  // DOM Elements
  const elements = {
    canvasContainer: document.getElementById('canvas-container'),
    canvasSvg: document.getElementById('statechart-canvas'),
    transformGroup: document.getElementById('canvas-transform-group'),
    edgesLayer: document.getElementById('edges-layer'),
    nodesLayer: document.getElementById('nodes-layer'),
    docAgentName: document.getElementById('doc-agent-name'),
    precursorSelect: document.getElementById('precursor-select'),
    targetSelect: document.getElementById('target-select'),
    btnVerifyDominance: document.getElementById('btn-verify-dominance'),
    themeSelect: document.getElementById('theme-select'),
    docEditionLabel: document.getElementById('doc-edition-label'),
    hudProofStatus: document.getElementById('hud-proof-status'),
    hudLatency: document.getElementById('hud-latency'),
    hudBypassRisk: document.getElementById('hud-bypass-risk'),
    btnZoomIn: document.getElementById('btn-zoom-in'),
    btnZoomOut: document.getElementById('btn-zoom-out'),
    btnZoomReset: document.getElementById('btn-zoom-reset'),
    btnReloadGraph: document.getElementById('btn-reload-graph'),
    btnExportCert: document.getElementById('btn-export-cert'),
    btnExportCode: document.getElementById('btn-export-code'),
    // Inspector elements
    inspStageName: document.getElementById('insp-stage-name'),
    inspStagePill: document.getElementById('insp-stage-pill'),
    inspStageType: document.getElementById('insp-stage-type'),
    inspStageTurns: document.getElementById('insp-stage-turns'),
    inspStageModel: document.getElementById('insp-stage-model'),
    inspStageDigressions: document.getElementById('insp-stage-digressions'),
    inspToolsContainer: document.getElementById('insp-tools-container'),
    inspFallbackRefusal: document.getElementById('insp-fallback-refusal'),
    inspFallbackTurns: document.getElementById('insp-fallback-turns'),
    inspFallbackBreach: document.getElementById('insp-fallback-breach'),
    inspFallbackSecurity: document.getElementById('insp-fallback-security'),
    inspDominanceSummary: document.getElementById('insp-dominance-summary'),
    // Trace elements
    traceSessionSelect: document.getElementById('trace-session-select'),
    traceTurnCounter: document.getElementById('trace-turn-counter'),
    traceChainStatus: document.getElementById('trace-chain-status'),
    traceStackDepth: document.getElementById('trace-stack-depth'),
    traceCurrentStage: document.getElementById('trace-current-stage'),
    traceSlotDeltas: document.getElementById('trace-slot-deltas'),
    traceToolsList: document.getElementById('trace-tools-list'),
    tracePrevHash: document.getElementById('trace-prev-hash'),
    traceCurrHash: document.getElementById('trace-curr-hash'),
    btnTraceFirst: document.getElementById('btn-trace-first'),
    btnTracePrev: document.getElementById('btn-trace-prev'),
    btnTraceNext: document.getElementById('btn-trace-next'),
    btnTraceLast: document.getElementById('btn-trace-last'),
    // Modals
    modalCert: document.getElementById('modal-cert'),
    modalCertClose: document.getElementById('modal-cert-close'),
    btnCloseCertFooter: document.getElementById('btn-close-cert-footer'),
    btnFetchCert: document.getElementById('btn-fetch-cert'),
    btnCopyCert: document.getElementById('btn-copy-cert'),
    certFormatSelect: document.getElementById('cert-format-select'),
    certContentView: document.getElementById('cert-content-view'),
    modalCode: document.getElementById('modal-code'),
    modalCodeClose: document.getElementById('modal-code-close'),
    btnCloseCodeFooter: document.getElementById('btn-close-code-footer'),
    btnCopyCode: document.getElementById('btn-copy-code'),
    codeContentView: document.getElementById('code-content-view')
  };

  // ==========================================================================
  // INITIALISATION & DATA FETCHING
  // ==========================================================================
  async function init() {
    setupEventListeners();
    await loadGraph();
    await loadTraces();

    // Query parameters for theme, precursor, target, and automated verification
    const params = new URLSearchParams(window.location.search);
    if (params.get('theme')) {
      const th = params.get('theme');
      document.documentElement.setAttribute('data-theme', th);
      elements.themeSelect.value = th;
      if (th === 'vellum') elements.docEditionLabel.textContent = 'I (ARCHIVAL VELLUM)';
      else if (th === 'cyanotype') elements.docEditionLabel.textContent = 'II (PRUSSIAN CYANOTYPE)';
      else if (th === 'swiss') elements.docEditionLabel.textContent = 'III (SWISS CONSTRUCTIVIST)';
    }
    if (params.get('precursor')) elements.precursorSelect.value = params.get('precursor');
    if (params.get('target')) elements.targetSelect.value = params.get('target');
    if (params.get('auto_verify') === '1' || (elements.precursorSelect.value && elements.targetSelect.value && params.get('verify') === '1')) {
      await verifyDominance();
    }
  }

  async function loadGraph() {
    try {
      const resp = await fetch('/api/graph');
      if (!resp.ok) {
        throw new Error(`Failed to load graph: ${resp.statusText}`);
      }
      const data = await resp.json();
      state.agentName = data.agent_name || 'BlockstateAgent';
      state.initialStage = data.initial_stage || '';
      state.stages = data.stages || {};
      state.transitions = data.transitions || [];

      elements.docAgentName.textContent = state.agentName;
      populateStageSelectors();
      calculateDagLayout();
      fitToView();
      renderTopology();

      // Default selection to initial stage
      if (state.initialStage && state.stages[state.initialStage]) {
        selectStage(state.initialStage);
      }
    } catch (err) {
      console.error('Error loading graph:', err);
      elements.docAgentName.textContent = 'Error Loading Agent';
    }
  }

  async function loadTraces() {
    try {
      const resp = await fetch('/api/traces');
      if (!resp.ok) return;
      const data = await resp.json();
      if (Array.isArray(data)) {
        state.traces = data;
        populateTraceSessions();
        if (state.traces.length > 0) {
          state.currentTraceIndex = 0;
          updateTraceScrubber();
        }
      }
    } catch (err) {
      console.warn('Trace loading notification:', err);
    }
  }

  // ==========================================================================
  // TOPOLOGY LAYOUT ENGINE (Hierarchical DAG Positioning)
  // ==========================================================================
  function calculateDagLayout() {
    const stageNames = Object.keys(state.stages);
    if (stageNames.length === 0) return;

    // Calculate topological levels starting from initial_stage
    const levels = {};
    const inDegree = {};
    stageNames.forEach(name => {
      levels[name] = 0;
      inDegree[name] = 0;
    });

    // Count in-degrees for standard transitions
    state.transitions.forEach(tr => {
      if (inDegree[tr.target] !== undefined && tr.target !== tr.source) {
        inDegree[tr.target]++;
      }
    });

    // Breadth-first level assignment
    const queue = [state.initialStage || stageNames[0]];
    const visited = new Set(queue);
    levels[queue[0]] = 0;

    while (queue.length > 0) {
      const curr = queue.shift();
      const currLevel = levels[curr] || 0;
      const outgoing = state.transitions
        .filter(t => t.source === curr && t.target !== curr && state.stages[t.target])
        .map(t => t.target);

      outgoing.forEach(target => {
        if (!visited.has(target)) {
          visited.add(target);
          levels[target] = Math.max(levels[target] || 0, currLevel + 1);
          queue.push(target);
        } else if ((levels[target] || 0) < currLevel + 1) {
          levels[target] = currLevel + 1;
        }
      });
    }

    // Assign unvisited fallback/disconnected stages to reasonable levels
    stageNames.forEach(name => {
      if (!visited.has(name)) {
        levels[name] = 1;
      }
    });

    // Group stages by level
    const levelBuckets = {};
    stageNames.forEach(name => {
      const lvl = levels[name];
      if (!levelBuckets[lvl]) levelBuckets[lvl] = [];
      levelBuckets[lvl].push(name);
    });

    // Compute coordinate positions symmetrically around the widest level
    const nodeWidth = 248;
    const nodeHeight = 94;
    const horizontalGap = 44;
    const verticalGap = 58;

    let maxRowWidth = 800;
    Object.keys(levelBuckets).forEach(lvlStr => {
      const row = levelBuckets[lvlStr];
      const rw = row.length * nodeWidth + (row.length - 1) * horizontalGap;
      if (rw > maxRowWidth) maxRowWidth = rw;
    });

    state.nodeLayout = {};
    Object.keys(levelBuckets).forEach(lvlStr => {
      const lvl = parseInt(lvlStr, 10);
      const row = levelBuckets[lvl];
      const rowWidth = row.length * nodeWidth + (row.length - 1) * horizontalGap;
      const startX = Math.max(32, (maxRowWidth - rowWidth) / 2);

      row.forEach((name, idx) => {
        const x = startX + idx * (nodeWidth + horizontalGap);
        const y = 24 + lvl * (nodeHeight + verticalGap);
        const stage = state.stages[name] || {};

        state.nodeLayout[name] = {
          name: name,
          level: lvl,
          x: Math.round(x),
          y: Math.round(y),
          width: nodeWidth,
          height: nodeHeight,
          stage: stage
        };
      });
    });
  }

  function fitToView() {
    const nodes = Object.values(state.nodeLayout);
    if (nodes.length === 0) return;

    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;

    nodes.forEach(n => {
      if (n.x < minX) minX = n.x;
      if (n.y < minY) minY = n.y;
      if (n.x + n.width + 8 > maxX) maxX = n.x + n.width + 8;
      if (n.y + n.height + 8 > maxY) maxY = n.y + n.height + 8;
    });

    const rect = elements.canvasContainer
      ? elements.canvasContainer.getBoundingClientRect()
      : { width: 1060, height: 620 };
    const availW = rect.width || 1060;
    const availH = rect.height || 620;

    const graphW = Math.max(1, maxX - minX);
    const graphH = Math.max(1, maxY - minY);

    const sideMargin = 36;
    const topMargin = graphH < 460 ? 104 : 20;
    const bottomMargin = 20;
    const leftClearance = graphH < 460 ? 36 : 120;

    const scaleX = (availW - leftClearance - sideMargin) / graphW;
    const scaleY = (availH - topMargin - bottomMargin) / graphH;
    const scale = Math.min(1.0, Math.max(0.55, Math.min(scaleX, scaleY)));

    state.zoom = Number(scale.toFixed(3));
    state.pan = {
      x: Math.round(leftClearance + (availW - leftClearance - sideMargin - graphW * state.zoom) / 2 - minX * state.zoom),
      y: Math.round(topMargin + (availH - topMargin - bottomMargin - graphH * state.zoom) / 2 - minY * state.zoom)
    };
  }

  // ==========================================================================
  // SVG TOPOLOGY RENDERING
  // ==========================================================================
  function renderTopology() {
    elements.edgesLayer.innerHTML = '';
    elements.nodesLayer.innerHTML = '';

    const nodes = state.nodeLayout;
    if (Object.keys(nodes).length === 0) return;

    // 1. Render directed transitions (deduplicated, excluding stay self-loops)
    const renderedEdges = new Set();
    state.transitions.forEach(tr => {
      if (tr.kind === 'stay' || tr.source === tr.target) return;
      const edgeKey = `${tr.source}->${tr.target}`;
      if (renderedEdges.has(edgeKey)) return;
      renderedEdges.add(edgeKey);

      const srcNode = nodes[tr.source];
      const dstNode = nodes[tr.target];
      if (!srcNode || !dstNode) return;

      const pathElem = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      let edgeClass = 'transition-edge';

      // Check if edge is on dominated path or bypass path
      if (state.proofResult) {
        if (state.proofResult.satisfied) {
          const isDominatedRoute = isEdgeOnDominatedRoute(tr.source, tr.target);
          if (isDominatedRoute) {
            edgeClass += ' transition-edge--dominated';
          }
        } else if (state.proofResult.violating_path) {
          const isBypass = isEdgeOnBypassPath(tr.source, tr.target, state.proofResult.violating_path);
          if (isBypass) {
            edgeClass += ' transition-edge--bypass';
          }
        }
      }

      pathElem.setAttribute('class', edgeClass);
      pathElem.setAttribute('data-source', tr.source);
      pathElem.setAttribute('data-target', tr.target);

      // Route path calculation
      const d = computeEdgePath(srcNode, dstNode);
      pathElem.setAttribute('d', d);
      elements.edgesLayer.appendChild(pathElem);

      // Render guard badge if conditional
      if (tr.guard) {
        const midX = (srcNode.x + srcNode.width / 2 + dstNode.x + dstNode.width / 2) / 2;
        const midY = (srcNode.y + srcNode.height + dstNode.y) / 2;

        const badgeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        bgRect.setAttribute('class', 'edge-guard-bg');
        bgRect.setAttribute('x', midX - 36);
        bgRect.setAttribute('y', midY - 10);
        bgRect.setAttribute('width', 72);
        bgRect.setAttribute('height', 18);
        bgRect.setAttribute('rx', 2);

        const txt = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        txt.setAttribute('class', 'edge-guard-badge');
        txt.setAttribute('x', midX);
        txt.setAttribute('y', midY + 3);
        txt.setAttribute('text-anchor', 'middle');
        txt.textContent = tr.guard;

        badgeGroup.appendChild(bgRect);
        badgeGroup.appendChild(txt);
        elements.edgesLayer.appendChild(badgeGroup);
      }
    });

    // 2. Render stage nodes
    Object.keys(nodes).forEach(name => {
      const node = nodes[name];
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      let nodeClasses = 'stage-node';
      if (state.selectedStage === name) nodeClasses += ' is-selected';
      if (state.precursorStage === name) nodeClasses += ' is-precursor';

      if (state.proofResult && state.targetStage === name) {
        if (state.proofResult.satisfied) {
          nodeClasses += ' is-target-protected';
        } else {
          nodeClasses += ' is-target-bypassed';
        }
      }

      g.setAttribute('class', nodeClasses);
      g.setAttribute('transform', `translate(${node.x}, ${node.y})`);
      g.setAttribute('data-stage-name', name);

      // Mechanical shadow rect (+4px offset)
      const shadow = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      shadow.setAttribute('class', 'stage-node-shadow');
      shadow.setAttribute('x', 4);
      shadow.setAttribute('y', 4);
      shadow.setAttribute('width', node.width);
      shadow.setAttribute('height', node.height);
      shadow.setAttribute('rx', 2);
      g.appendChild(shadow);

      // Card body rect
      const card = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      card.setAttribute('class', 'stage-node-card');
      card.setAttribute('x', 0);
      card.setAttribute('y', 0);
      card.setAttribute('width', node.width);
      card.setAttribute('height', node.height);
      card.setAttribute('rx', 2);
      g.appendChild(card);

      // Card header band
      const header = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      header.setAttribute('class', 'stage-node-header');
      header.setAttribute('x', 0);
      header.setAttribute('y', 0);
      header.setAttribute('width', node.width);
      header.setAttribute('height', 30);
      header.setAttribute('rx', 2);
      g.appendChild(header);

      // Header title text
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      title.setAttribute('class', 'stage-node-title');
      title.setAttribute('x', 12);
      title.setAttribute('y', 16);
      title.textContent = truncateText(name, 22);
      g.appendChild(title);

      // Status indicator pill in header
      const pill = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      pill.setAttribute('class', 'stage-node-subtitle');
      pill.setAttribute('x', node.width - 12);
      pill.setAttribute('y', 16);
      pill.setAttribute('text-anchor', 'end');
      pill.setAttribute('font-weight', '700');

      if (node.stage.is_initial || name === state.initialStage) {
        pill.textContent = '[INIT]';
        pill.setAttribute('fill', 'var(--signal-cobalt)');
      } else if (node.stage.terminal) {
        pill.textContent = '[TERM]';
        pill.setAttribute('fill', 'var(--signal-vermilion)');
      } else {
        pill.textContent = '[STD]';
        pill.setAttribute('fill', 'var(--text-muted)');
      }
      g.appendChild(pill);

      // Body tools container summary
      const tools = node.stage.tools || [];
      const toolText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      toolText.setAttribute('class', 'stage-node-subtitle');
      toolText.setAttribute('x', 12);
      toolText.setAttribute('y', 52);
      if (tools.length === 0) {
        toolText.textContent = 'Tools: (none exposed)';
        toolText.setAttribute('fill', 'var(--text-muted)');
      } else {
        toolText.textContent = `Tools: ${tools.slice(0, 2).join(', ')}${tools.length > 2 ? '...' : ''}`;
        toolText.setAttribute('fill', 'var(--signal-vermilion)');
        toolText.setAttribute('font-weight', '600');
      }
      g.appendChild(toolText);

      // Digressions / Fallback summary
      const fallbackText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      fallbackText.setAttribute('class', 'stage-node-subtitle');
      fallbackText.setAttribute('x', 12);
      fallbackText.setAttribute('y', 74);
      if (node.stage.collect_model) {
        fallbackText.textContent = `Slots: ${node.stage.collect_model}`;
        fallbackText.setAttribute('fill', 'var(--text-secondary)');
      } else if (node.stage.allow_digressions && node.stage.allow_digressions.length > 0) {
        fallbackText.textContent = `Digressions: ${node.stage.allow_digressions.join(', ')}`;
        fallbackText.setAttribute('fill', 'var(--signal-ochre)');
      } else {
        fallbackText.textContent = `Max Turns: ${node.stage.max_turns || 'unlimited'}`;
        fallbackText.setAttribute('fill', 'var(--text-muted)');
      }
      g.appendChild(fallbackText);

      // Corner Crosshairs (Architectural Drafting Detail)
      renderDraftingCrosshair(g, 0, 0);
      renderDraftingCrosshair(g, node.width, 0);
      renderDraftingCrosshair(g, 0, node.height);
      renderDraftingCrosshair(g, node.width, node.height);

      // Interaction listeners
      g.addEventListener('click', (e) => {
        e.stopPropagation();
        selectStage(name);
      });

      elements.nodesLayer.appendChild(g);
    });

    updateTransform();
  }

  function computeEdgePath(src, dst) {
    // If self-loop
    if (src.name === dst.name) {
      const x = src.x + src.width - 24;
      const y = src.y;
      return `M ${x} ${y} C ${x + 36} ${y - 36}, ${x + 56} ${y + 24}, ${x + 20} ${y + 24}`;
    }

    const srcBottomX = src.x + src.width / 2;
    const srcBottomY = src.y + src.height;
    const dstTopX = dst.x + dst.width / 2;
    const dstTopY = dst.y;

    if (dstTopY >= srcBottomY) {
      const midY = (srcBottomY + dstTopY) / 2;
      // If edge spans multiple levels, check if any intermediate node obstructs the direct curve
      if (dstTopY - srcBottomY > 110) {
        const minX = Math.min(srcBottomX, dstTopX) - 24;
        const maxX = Math.max(srcBottomX, dstTopX) + 24;
        const obstructingNodes = Object.values(state.nodeLayout).filter(n => (
          n.name !== src.name &&
          n.name !== dst.name &&
          n.y > src.y &&
          n.y < dst.y &&
          n.x + n.width >= minX &&
          n.x <= maxX
        ));
        if (obstructingNodes.length > 0) {
          const obsMinX = Math.min(...obstructingNodes.map(n => n.x));
          const startX = src.x + 36;
          const ctrlX = obsMinX - 56;
          return `M ${startX} ${srcBottomY} C ${ctrlX} ${srcBottomY + 32}, ${ctrlX} ${dstTopY - 32}, ${dstTopX - 24} ${dstTopY}`;
        }
      }
      return `M ${srcBottomX} ${srcBottomY} C ${srcBottomX} ${midY}, ${dstTopX} ${midY}, ${dstTopX} ${dstTopY}`;
    } else {
      // Loop backwards / sideways
      const offset = 48;
      const srcRightX = src.x + src.width;
      const srcMidY = src.y + src.height / 2;
      const dstRightX = dst.x + dst.width;
      const dstMidY = dst.y + dst.height / 2;
      return `M ${srcRightX} ${srcMidY} C ${srcRightX + offset} ${srcMidY}, ${dstRightX + offset} ${dstMidY}, ${dstRightX} ${dstMidY}`;
    }
  }

  function renderDraftingCrosshair(parent, x, y) {
    const size = 3;
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M ${x - size} ${y} L ${x + size} ${y} M ${x} ${y - size} L ${x} ${y + size}`);
    path.setAttribute('stroke', 'var(--border-strong)');
    path.setAttribute('stroke-width', '1');
    parent.appendChild(path);
  }

  function truncateText(str, maxLen) {
    if (!str) return '';
    return str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : str;
  }

  function isEdgeOnDominatedRoute(src, dst) {
    if (!state.proofResult || !state.precursorStage || !state.targetStage) return false;
    const idoms = state.proofResult.immediate_dominators || {};
    const chainNodes = new Set([state.targetStage, state.precursorStage, state.initialStage]);
    let curr = state.targetStage;
    let safety = 0;
    while (curr && idoms[curr] && idoms[curr] !== curr && safety < 50) {
      chainNodes.add(idoms[curr]);
      curr = idoms[curr];
      safety++;
    }
    if (idoms[dst] === src && chainNodes.has(dst)) return true;
    if (chainNodes.has(src) && dst === state.targetStage) return true;
    if (chainNodes.has(src) && idoms[src] === state.precursorStage && dst === state.targetStage) return true;
    if (src === state.precursorStage && dst === state.targetStage) return true;
    if (src === state.initialStage && dst === state.precursorStage) return true;
    // Also highlight intermediate stage edges that strictly lie between an idom ancestor and targetStage
    if (chainNodes.has(src) && idoms[dst] === src) return true;
    if (idoms[src] && chainNodes.has(idoms[src]) && dst === state.targetStage) return true;
    return false;
  }

  function isEdgeOnBypassPath(src, dst, path) {
    if (!Array.isArray(path) || path.length < 2) return false;
    for (let i = 0; i < path.length - 1; i++) {
      if (path[i] === src && path[i + 1] === dst) return true;
    }
    return false;
  }

  // ==========================================================================
  // STAGE INSPECTION & SELECTION
  // ==========================================================================
  function selectStage(name) {
    state.selectedStage = name;
    const stage = state.stages[name];
    if (!stage) return;

    elements.inspStageName.textContent = name;

    // Pill
    if (stage.is_initial || name === state.initialStage) {
      elements.inspStagePill.textContent = 'INITIAL';
      elements.inspStagePill.className = 'status-pill status-pill--initial';
    } else if (stage.terminal) {
      elements.inspStagePill.textContent = 'TERMINAL';
      elements.inspStagePill.className = 'status-pill status-pill--terminal';
    } else {
      elements.inspStagePill.textContent = 'STANDARD';
      elements.inspStagePill.className = 'status-pill status-pill--standard';
    }

    elements.inspStageType.textContent = stage.is_initial ? 'Initial Entrypoint' : (stage.terminal ? 'Terminal State' : 'Standard Stage');
    elements.inspStageTurns.textContent = stage.max_turns ? `${stage.max_turns} turns` : 'Unlimited';
    elements.inspStageModel.textContent = stage.collect_model || 'None';
    elements.inspStageDigressions.textContent = (stage.allow_digressions && stage.allow_digressions.length > 0)
      ? stage.allow_digressions.join(', ')
      : 'None';

    // Fallbacks
    elements.inspFallbackRefusal.textContent = stage.on_refusal ? `-> ${stage.on_refusal}` : 'N/A';
    elements.inspFallbackTurns.textContent = stage.on_max_turns_exceeded ? `-> ${stage.on_max_turns_exceeded}` : 'N/A';
    elements.inspFallbackBreach.textContent = stage.on_breach ? `-> ${stage.on_breach}` : 'N/A';
    elements.inspFallbackSecurity.textContent = stage.on_security_violation ? `-> ${stage.on_security_violation}` : 'N/A';

    // Tool gatekeeper badges
    elements.inspToolsContainer.innerHTML = '';
    const tools = stage.tools || [];
    if (tools.length === 0) {
      elements.inspToolsContainer.innerHTML = '<span style="font-size: 11px; color: var(--text-muted); font-style: italic;">No tools exposed in memory for this stage</span>';
    } else {
      tools.forEach(t => {
        const badge = document.createElement('span');
        badge.className = 'tool-badge';
        badge.textContent = t;
        elements.inspToolsContainer.appendChild(badge);
      });
    }

    renderTopology();
  }

  function populateStageSelectors() {
    const stageNames = Object.keys(state.stages);

    elements.precursorSelect.innerHTML = '<option value="">(Select Precursor)</option>';
    elements.targetSelect.innerHTML = '<option value="">(Select Target)</option>';

    stageNames.forEach(name => {
      const optPre = document.createElement('option');
      optPre.value = name;
      optPre.textContent = name;
      elements.precursorSelect.appendChild(optPre);

      const optTgt = document.createElement('option');
      optTgt.value = name;
      optTgt.textContent = name;
      elements.targetSelect.appendChild(optTgt);
    });

    // Auto-select realistic defaults if present (e.g. KYC and transfer)
    if (stageNames.includes('verify_identity')) {
      elements.precursorSelect.value = 'verify_identity';
      state.precursorStage = 'verify_identity';
    } else if (stageNames.includes('verify_kyc')) {
      elements.precursorSelect.value = 'verify_kyc';
      state.precursorStage = 'verify_kyc';
    } else if (stageNames.includes('step_up_mfa_kyc')) {
      elements.precursorSelect.value = 'step_up_mfa_kyc';
      state.precursorStage = 'step_up_mfa_kyc';
    } else if (state.initialStage && stageNames.includes(state.initialStage)) {
      elements.precursorSelect.value = state.initialStage;
      state.precursorStage = state.initialStage;
    }

    if (stageNames.includes('execute_transfer')) {
      elements.targetSelect.value = 'execute_transfer';
      state.targetStage = 'execute_transfer';
    } else if (stageNames.includes('faster_payments_uk')) {
      elements.targetSelect.value = 'faster_payments_uk';
      state.targetStage = 'faster_payments_uk';
    }
  }

  // ==========================================================================
  // REAL-TIME LENGAUER-TARJAN DOMINANCE VERIFICATION
  // ==========================================================================
  async function verifyDominance() {
    const precursor = elements.precursorSelect.value;
    const target = elements.targetSelect.value;

    if (!precursor || !target) {
      alert('Please select both a precursor stage and a target stage.');
      return;
    }

    state.precursorStage = precursor;
    state.targetStage = target;

    try {
      const resp = await fetch('/api/verify-dominance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ precursor: precursor, target: target })
      });

      if (!resp.ok) {
        throw new Error(`Verification endpoint failed: ${resp.statusText}`);
      }

      const data = await resp.json();
      state.proofResult = data;

      // Update HUD Status
      elements.hudLatency.textContent = `${data.elapsed_ms.toFixed(2)}ms`;

      if (data.satisfied) {
        elements.hudProofStatus.textContent = 'DOMINATED (Exit Code 0)';
        elements.hudProofStatus.className = 'hud-val hud-val--verified';
        elements.hudBypassRisk.textContent = '0.00% (Mathematical Invariant)';
        elements.hudBypassRisk.className = 'hud-val hud-val--verified';
      } else {
        elements.hudProofStatus.textContent = 'BYPASS DETECTED (Exit Code 1)';
        elements.hudProofStatus.className = 'hud-val hud-val--violation';
        elements.hudBypassRisk.textContent = '100.00% (Vulnerability Path)';
        elements.hudBypassRisk.className = 'hud-val hud-val--violation';
      }

      // Update Inspector Dominance Summary
      elements.inspDominanceSummary.innerHTML = `
        <div style="font-weight: 700; margin-bottom: 4px; color: ${data.satisfied ? 'var(--signal-clear)' : 'var(--signal-vermilion)'};">
          ${data.satisfied ? 'Mathematical Invariant Certified' : 'Dominance Invariant Violated'}
        </div>
        <p>${data.summary}</p>
        ${data.violating_path ? `<p style="margin-top: 6px; font-family: var(--font-mono); font-size: 11px; color: var(--signal-vermilion);">Route: ${data.violating_path.join(' &rarr; ')}</p>` : ''}
      `;

      renderTopology();
    } catch (err) {
      console.error('Error during dominance verification:', err);
      elements.hudProofStatus.textContent = 'VERIFICATION ERROR';
      elements.hudProofStatus.className = 'hud-val hud-val--violation';
    }
  }

  // ==========================================================================
  // TRACE INSPECTOR & HASH REPLAY
  // ==========================================================================
  function populateTraceSessions() {
    elements.traceSessionSelect.innerHTML = '';
    if (state.traces.length === 0) {
      elements.traceSessionSelect.innerHTML = '<option value="">No traces recorded</option>';
      return;
    }

    const sessionOpt = document.createElement('option');
    sessionOpt.value = 'default';
    sessionOpt.textContent = `Recorded Session (${state.traces.length} Turns)`;
    elements.traceSessionSelect.appendChild(sessionOpt);
  }

  function updateTraceScrubber() {
    const total = state.traces.length;
    if (total === 0) {
      elements.traceTurnCounter.textContent = 'Turn 0 / 0';
      return;
    }

    const idx = state.currentTraceIndex;
    const rec = state.traces[idx];
    elements.traceTurnCounter.textContent = `Turn ${idx + 1} / ${total}`;

    // Update scrubber buttons
    elements.btnTraceFirst.disabled = (idx === 0);
    elements.btnTracePrev.disabled = (idx === 0);
    elements.btnTraceNext.disabled = (idx === total - 1);
    elements.btnTraceLast.disabled = (idx === total - 1);

    // Populate Card 1: TaskStack & Slot Deltas
    elements.traceCurrentStage.textContent = rec.stage || rec.stage_to || rec.stage_from || 'N/A';
    const stack = rec.task_stack || ['Mainline'];
    elements.traceStackDepth.textContent = `Depth ${stack.length}`;
    elements.traceSlotDeltas.textContent = (rec.slot_deltas && rec.slot_deltas.length > 0)
      ? rec.slot_deltas.join(', ')
      : (rec.slots ? JSON.stringify(rec.slots) : 'none');

    // Populate Card 2: Ephemeral Tool Whitelist
    elements.traceToolsList.innerHTML = '';
    const exposed = rec.exposed_tools || [];
    if (exposed.length === 0) {
      elements.traceToolsList.innerHTML = '<span style="font-size: 11px; color: var(--text-muted); font-style: italic;">No tools exposed in memory</span>';
    } else {
      exposed.forEach(t => {
        const badge = document.createElement('span');
        badge.className = 'tool-badge';
        badge.textContent = t;
        elements.traceToolsList.appendChild(badge);
      });
    }

    // Populate Card 3: Cryptographic TurnLedger Chain
    elements.tracePrevHash.textContent = rec.prev_record_hash || '0'.repeat(64);
    elements.traceCurrHash.textContent = rec.record_hash || 'e3b0c44298fc1c14...';

    // Verify hash continuity
    let isValidChain = true;
    if (idx === 0) {
      isValidChain = (!rec.prev_record_hash || rec.prev_record_hash === '0'.repeat(64));
    } else {
      const prevRec = state.traces[idx - 1];
      isValidChain = (rec.prev_record_hash === prevRec.record_hash);
    }

    if (isValidChain) {
      elements.traceChainStatus.textContent = 'CHAIN VALID';
      elements.traceChainStatus.className = 'status-pill status-pill--initial';
    } else {
      elements.traceChainStatus.textContent = 'CHAIN BROKEN';
      elements.traceChainStatus.className = 'status-pill status-pill--terminal';
    }

    // Auto-focus canvas stage if matches
    const stageName = rec.stage || rec.stage_to;
    if (stageName && state.stages[stageName]) {
      selectStage(stageName);
    }
  }

  // ==========================================================================
  // AUDIT CERTIFICATE & CODE EXPORT
  // ==========================================================================
  async function fetchAuditCertificate() {
    const precursor = state.precursorStage || elements.precursorSelect.value || state.initialStage;
    const target = state.targetStage || elements.targetSelect.value || Object.keys(state.stages)[1];
    const fmt = elements.certFormatSelect.value;

    elements.certContentView.textContent = 'Generating audit certificate...';
    elements.modalCert.classList.add('is-open');

    try {
      const resp = await fetch('/api/export-certificate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          precursor: precursor,
          targets: [target],
          format: fmt
        })
      });

      if (!resp.ok) {
        throw new Error(`Certificate export failed: ${resp.statusText}`);
      }

      const data = await resp.json();
      if (fmt === 'json') {
        elements.certContentView.textContent = JSON.stringify(data.certificate, null, 2);
      } else {
        elements.certContentView.textContent = data.certificate;
      }
    } catch (err) {
      elements.certContentView.textContent = `Error generating certificate: ${err.message}`;
    }
  }

  async function fetchExportCode() {
    elements.codeContentView.textContent = 'Synthesising deterministic Python 3.12+ source code...';
    elements.modalCode.classList.add('is-open');

    try {
      // Build spec from current state
      const spec = {
        agent_name: state.agentName,
        initial_stage: state.initialStage,
        stages: Object.keys(state.stages).map(name => {
          const s = state.stages[name];
          const outTransitions = state.transitions
            .filter(t => t.source === name)
            .map(t => ({ target: t.target, guard: t.guard }));

          return {
            name: name,
            is_initial: (name === state.initialStage),
            terminal: !!s.terminal,
            tools: s.tools || [],
            transitions: outTransitions.length > 0 ? outTransitions : [{ target: '[END]' }]
          };
        })
      };

      const resp = await fetch('/api/export-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ spec: spec })
      });

      if (!resp.ok) {
        throw new Error(`Code export failed: ${resp.statusText}`);
      }

      const data = await resp.json();
      elements.codeContentView.textContent = data.python_source;
    } catch (err) {
      elements.codeContentView.textContent = `Error exporting code: ${err.message}`;
    }
  }

  // ==========================================================================
  // EVENT LISTENERS & INTERACTION
  // ==========================================================================
  function setupEventListeners() {
    // Canvas Pan & Zoom
    elements.canvasContainer.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      state.isPanning = true;
      state.startPan = { x: e.clientX - state.pan.x, y: e.clientY - state.pan.y };
    });

    window.addEventListener('mousemove', (e) => {
      if (!state.isPanning) return;
      state.pan.x = e.clientX - state.startPan.x;
      state.pan.y = e.clientY - state.startPan.y;
      updateTransform();
    });

    window.addEventListener('mouseup', () => {
      state.isPanning = false;
    });

    elements.canvasContainer.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      state.zoom = Math.min(3.0, Math.max(0.3, state.zoom * zoomFactor));
      updateTransform();
    }, { passive: false });

    elements.btnZoomIn.addEventListener('click', () => {
      state.zoom = Math.min(3.0, state.zoom * 1.2);
      updateTransform();
    });

    elements.btnZoomOut.addEventListener('click', () => {
      state.zoom = Math.max(0.3, state.zoom / 1.2);
      updateTransform();
    });

    elements.btnZoomReset.addEventListener('click', () => {
      fitToView();
      updateTransform();
    });

    // Theme selector
    elements.themeSelect.addEventListener('change', (e) => {
      const theme = e.target.value;
      document.documentElement.setAttribute('data-theme', theme);
      if (theme === 'vellum') elements.docEditionLabel.textContent = 'I (ARCHIVAL VELLUM)';
      else if (theme === 'cyanotype') elements.docEditionLabel.textContent = 'II (PRUSSIAN CYANOTYPE)';
      else if (theme === 'swiss') elements.docEditionLabel.textContent = 'III (SWISS CONSTRUCTIVIST)';
    });

    // Dominance verification button
    elements.btnVerifyDominance.addEventListener('click', verifyDominance);

    // Reload button
    elements.btnReloadGraph.addEventListener('click', () => {
      loadGraph();
      loadTraces();
    });

    // Scrubber controls
    elements.btnTraceFirst.addEventListener('click', () => {
      state.currentTraceIndex = 0;
      updateTraceScrubber();
    });
    elements.btnTracePrev.addEventListener('click', () => {
      if (state.currentTraceIndex > 0) {
        state.currentTraceIndex--;
        updateTraceScrubber();
      }
    });
    elements.btnTraceNext.addEventListener('click', () => {
      if (state.currentTraceIndex < state.traces.length - 1) {
        state.currentTraceIndex++;
        updateTraceScrubber();
      }
    });
    elements.btnTraceLast.addEventListener('click', () => {
      if (state.traces.length > 0) {
        state.currentTraceIndex = state.traces.length - 1;
        updateTraceScrubber();
      }
    });

    // Modals
    elements.btnExportCert.addEventListener('click', fetchAuditCertificate);
    elements.btnFetchCert.addEventListener('click', fetchAuditCertificate);
    elements.modalCertClose.addEventListener('click', () => elements.modalCert.classList.remove('is-open'));
    elements.btnCloseCertFooter.addEventListener('click', () => elements.modalCert.classList.remove('is-open'));
    elements.btnCopyCert.addEventListener('click', () => {
      navigator.clipboard.writeText(elements.certContentView.textContent);
      elements.btnCopyCert.textContent = 'Copied!';
      setTimeout(() => elements.btnCopyCert.textContent = 'Copy to Clipboard', 2000);
    });

    elements.btnExportCode.addEventListener('click', fetchExportCode);
    elements.modalCodeClose.addEventListener('click', () => elements.modalCode.classList.remove('is-open'));
    elements.btnCloseCodeFooter.addEventListener('click', () => elements.modalCode.classList.remove('is-open'));
    elements.btnCopyCode.addEventListener('click', () => {
      navigator.clipboard.writeText(elements.codeContentView.textContent);
      elements.btnCopyCode.textContent = 'Copied!';
      setTimeout(() => elements.btnCopyCode.textContent = 'Copy Python Source', 2000);
    });
  }

  function updateTransform() {
    elements.transformGroup.setAttribute(
      'transform',
      `translate(${state.pan.x}, ${state.pan.y}) scale(${state.zoom})`
    );
  }

  // Initialise on load
  document.addEventListener('DOMContentLoaded', init);
})();
