/**
 * CyberGuard SOC Dashboard Client Application
 */

(function () {
  let currentCampaigns = [];
  let selectedCampaignId = null;
  let attackGraphData = { nodes: [], edges: [] };
  let graphAnimationId = null;

  // Initialize
  document.addEventListener("DOMContentLoaded", () => {
    setupDropZone();
    loadDashboardData();
    // Auto refresh every 15s
    setInterval(loadDashboardData, 15000);
  });

  // =========================================================================
  // DATA FETCHING & KPI REFRESH
  // =========================================================================

  async function loadDashboardData() {
    try {
      const [statsRes, campaignsRes] = await Promise.all([
        fetch("/api/stats"),
        fetch("/api/campaigns")
      ]);

      if (statsRes.ok) {
        const stats = await statsRes.json();
        updateKpis(stats);
      }

      if (campaignsRes.ok) {
        currentCampaigns = await campaignsRes.json();
        renderCampaignsList(currentCampaigns);

        // Auto select first campaign if none selected
        if (!selectedCampaignId && currentCampaigns.length > 0) {
          selectCampaign(currentCampaigns[0].campaign_id);
        } else if (selectedCampaignId) {
          // Re-render selected campaign details
          const active = currentCampaigns.find(c => c.campaign_id === selectedCampaignId);
          if (active) renderCampaignDetail(active);
        }
      }
    } catch (err) {
      console.error("Failed to load dashboard telemetry:", err);
    }
  }

  function updateKpis(stats) {
    document.getElementById("valTotalCampaigns").textContent = stats.total_campaigns || 0;
    document.getElementById("valCriticalCampaigns").textContent = stats.critical_campaigns || 0;
    document.getElementById("valTotalEvents").textContent = stats.total_events || 0;
    document.getElementById("campaignCountBadge").textContent = `${stats.total_campaigns || 0} Campaigns`;
  }

  // =========================================================================
  // CAMPAIGNS LIST RENDERING
  // =========================================================================

  function renderCampaignsList(campaigns) {
    const container = document.getElementById("campaignsList");
    if (!campaigns || campaigns.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <p>No active attack campaigns recorded.<br>Ingest a file or load a preset scenario above.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = campaigns.map(c => {
      const isSelected = c.campaign_id === selectedCampaignId;
      const riskLevel = (c.risk_level || "low").toLowerCase();
      const riskScore = c.risk_score || 0;
      const eventCount = c.event_count || c.events.length;
      const engines = [...new Set(c.events.map(e => e.source_engine))].join(" • ");

      return `
        <div class="campaign-card ${isSelected ? 'selected' : ''}" onclick="window.selectCampaign('${c.campaign_id}')">
          <div class="card-top-row">
            <span class="card-cid">${c.campaign_id}</span>
            <span class="severity-pill ${riskLevel}">${riskLevel.toUpperCase()} (${riskScore})</span>
          </div>
          <h3 class="card-title">${escapeHtml(c.title || 'Multi-Stage Incident')}</h3>
          <div class="card-footer">
            <span>${engines}</span>
            <span>${eventCount} event${eventCount > 1 ? 's' : ''}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  window.selectCampaign = async function (campaignId) {
    selectedCampaignId = campaignId;
    renderCampaignsList(currentCampaigns);

    try {
      const res = await fetch(`/api/campaigns/${campaignId}`);
      if (res.ok) {
        const campaign = await res.json();
        renderCampaignDetail(campaign);
      }

      // Fetch attack graph
      const graphRes = await fetch(`/api/campaigns/${campaignId}/graph`);
      if (graphRes.ok) {
        attackGraphData = await graphRes.json();
        renderAttackGraph(attackGraphData);
      }
    } catch (err) {
      console.error("Failed to fetch campaign detail:", err);
    }
  };

  // =========================================================================
  // CAMPAIGN DETAIL VIEW RENDERING
  // =========================================================================

  function renderCampaignDetail(campaign) {
    document.getElementById("detailEmptyView").style.display = "none";
    document.getElementById("detailContentView").style.display = "flex";

    // Title & Badges
    document.getElementById("detailCampaignTitle").textContent = campaign.title || campaign.campaign_id;
    const riskLevel = (campaign.risk_level || "low").toLowerCase();
    
    // Risk Card
    document.getElementById("riskScoreVal").textContent = campaign.risk_score || "0";
    const riskBadge = document.getElementById("riskLevelBadge");
    riskBadge.textContent = riskLevel.toUpperCase();
    riskBadge.className = `gauge-badge severity-pill ${riskLevel}`;
    document.getElementById("riskProgressFill").style.width = `${Math.min(campaign.risk_score || 0, 100)}%`;

    // Entities Grid
    const entitiesGrid = document.getElementById("entitiesGrid");
    const entityEntries = Object.entries(campaign.entities || {});
    if (entityEntries.length === 0) {
      entitiesGrid.innerHTML = `<span style="font-size: 12px; color: var(--text-muted);">None extracted</span>`;
    } else {
      entitiesGrid.innerHTML = entityEntries.flatMap(([type, vals]) => {
        return (vals || []).map(val => `
          <div class="entity-pill">
            <span class="entity-type-tag">${escapeHtml(type)}:</span>
            <span>${escapeHtml(String(val))}</span>
          </div>
        `);
      }).join("");
    }

    // MITRE ATT&CK Badges
    const mitreList = document.getElementById("mitreTagsList");
    const mitreTechniques = campaign.mitre_techniques || [];
    if (mitreTechniques.length === 0) {
      mitreList.innerHTML = `<span style="font-size: 12px; color: var(--text-muted);">No MITRE mappings recorded</span>`;
    } else {
      mitreList.innerHTML = mitreTechniques.map(m => `
        <div class="mitre-badge">
          <span class="mitre-id">${m.id}</span>
          <span class="mitre-name">${escapeHtml(m.name)}</span>
          <span class="mitre-tactic">${escapeHtml(m.tactic)}</span>
        </div>
      `).join("");
    }

    // Explainable AI
    const xai = campaign.explanation || {};
    document.getElementById("xaiExecSummary").textContent = xai.executive_summary || "Analysis pending...";

    const narrativeWrap = document.getElementById("xaiNarrativeContent");
    const narrativeText = xai.attack_narrative || "";
    if (narrativeText) {
      const steps = narrativeText.split("\n\n");
      narrativeWrap.innerHTML = steps.map(s => `
        <div class="narrative-step-item">${escapeHtml(s)}</div>
      `).join("");
    } else {
      narrativeWrap.innerHTML = `<p style="font-size: 12px; color: var(--text-muted);">No chronological narrative available.</p>`;
    }

    // Evidence Breakdown Table
    const evidenceTbody = document.getElementById("evidenceTableBody");
    const evidenceItems = xai.evidence_breakdown || [];
    if (evidenceItems.length === 0) {
      evidenceTbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No forensic signals found</td></tr>`;
    } else {
      evidenceTbody.innerHTML = evidenceItems.map(item => {
        const weight = item.weight || 0.0;
        const badgeClass = weight >= 0.5 ? "high" : (weight >= 0.3 ? "med" : "low");
        return `
          <tr>
            <td><strong style="color: var(--accent-cyan); text-transform: uppercase;">${escapeHtml(item.source_engine || 'unknown')}</strong></td>
            <td><span class="weight-badge ${badgeClass}">${(weight * 100).toFixed(0)}%</span></td>
            <td>${escapeHtml(item.description || '')}</td>
          </tr>
        `;
      }).join("");
    }

    // Incident Response Playbook
    const recommendedAction = campaign.response_recommended || "quarantine_email";
    const playbook = (window.PLAYBOOKS && window.PLAYBOOKS[recommendedAction]) || {
      title: "Automated Incident Containment",
      priority: "P0",
      description: "Execute targeted isolation and access revocation across affected accounts and network endpoints.",
      steps: [
        "Revoke active OAuth & SSO sessions",
        "Block malicious communication nodes at firewall edge",
        "Quarantine malicious payloads across endpoints"
      ]
    };

    document.getElementById("playbookTitle").textContent = playbook.title;
    document.getElementById("playbookDesc").textContent = playbook.description;
    document.getElementById("playbookPriority").textContent = `${playbook.priority || 'P0'} HIGH PRIORITY`;
    document.getElementById("playbookSteps").innerHTML = (playbook.steps || []).map(s => `<li>${escapeHtml(s)}</li>`).join("");
    document.getElementById("responseStatusLog").style.display = "none";

    // Events Accordion
    document.getElementById("eventCountBadge").textContent = campaign.events.length;
    const accordion = document.getElementById("eventsAccordion");
    accordion.innerHTML = campaign.events.map((ev, i) => `
      <div class="event-accordion-item">
        <div class="event-item-header" onclick="window.toggleAccordion('ev_${i}')">
          <span><strong>[${ev.source_engine.toUpperCase()}]</strong> ${escapeHtml(ev.event_type)}</span>
          <span style="color: var(--text-muted); font-size: 11px;">Confidence: ${(ev.confidence * 100).toFixed(0)}% • ${ev.timestamp}</span>
        </div>
        <div class="event-item-body" id="ev_${i}" style="display: none;">
          ${escapeHtml(JSON.stringify(ev, null, 2))}
        </div>
      </div>
    `).join("");
  }

  window.toggleAccordion = function (id) {
    const el = document.getElementById(id);
    if (el) {
      el.style.display = el.style.display === "none" ? "block" : "none";
    }
  };

  // =========================================================================
  // INTERACTIVE ATTACK GRAPH CANVAS
  // =========================================================================

  function renderAttackGraph(graph) {
    const canvas = document.getElementById("attackGraphCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    // Cancel existing loop
    if (graphAnimationId) cancelAnimationFrame(graphAnimationId);

    const width = canvas.width = canvas.parentElement.clientWidth || 800;
    const height = canvas.height = 340;

    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    if (nodes.length === 0) {
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = "#64748b";
      ctx.font = "13px Inter";
      ctx.textAlign = "center";
      ctx.fillText("No attack graph nodes available for this campaign.", width / 2, height / 2);
      return;
    }

    // Position calculation
    const eventNodes = nodes.filter(n => n.type === "event");
    const entityNodes = nodes.filter(n => n.type === "entity");

    const nodePositions = {};

    // Layout event nodes along top/middle arc
    const eventSpacing = width / (eventNodes.length + 1);
    eventNodes.forEach((node, i) => {
      nodePositions[node.id] = {
        x: eventSpacing * (i + 1),
        y: 100 + (i % 2 === 0 ? -25 : 25),
        radius: 24,
        node: node
      };
    });

    // Layout entity nodes along bottom row
    const entitySpacing = width / (entityNodes.length + 1);
    entityNodes.forEach((node, i) => {
      nodePositions[node.id] = {
        x: entitySpacing * (i + 1),
        y: 250 + (i % 2 === 0 ? 15 : -15),
        radius: 18,
        node: node
      };
    });

    let pulseTime = 0;

    function draw() {
      pulseTime += 0.03;
      ctx.clearRect(0, 0, width, height);

      // Draw Edges
      edges.forEach(edge => {
        const src = nodePositions[edge.source];
        const tgt = nodePositions[edge.target];
        if (!src || !tgt) return;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);

        if (edge.type === "progression") {
          ctx.strokeStyle = "rgba(0, 242, 254, 0.6)";
          ctx.lineWidth = 2.5;
          ctx.setLineDash([6, 4]);
        } else {
          ctx.strokeStyle = "rgba(139, 92, 246, 0.35)";
          ctx.lineWidth = 1.5;
          ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Animated packet dot
        const t = (pulseTime + (edge.id.length * 0.1)) % 1;
        const px = src.x + (tgt.x - src.x) * t;
        const py = src.y + (tgt.y - src.y) * t;
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI * 2);
        ctx.fillStyle = edge.type === "progression" ? "#00f2fe" : "#8b5cf6";
        ctx.fill();
      });

      // Draw Nodes
      Object.values(nodePositions).forEach(pos => {
        const isEvent = pos.node.type === "event";

        // Outer glow
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, pos.radius + 4, 0, Math.PI * 2);
        ctx.fillStyle = isEvent ? "rgba(0, 242, 254, 0.15)" : "rgba(139, 92, 246, 0.15)";
        ctx.fill();

        // Node Circle
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, pos.radius, 0, Math.PI * 2);
        ctx.fillStyle = isEvent ? "#0f172a" : "#1e1b4b";
        ctx.strokeStyle = isEvent ? "#00f2fe" : "#8b5cf6";
        ctx.lineWidth = 2;
        ctx.fill();
        ctx.stroke();

        // Icon/Text inside node
        ctx.fillStyle = "#f8fafc";
        ctx.font = "10px Inter";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";

        const label = pos.node.label || "";
        const truncated = label.length > 18 ? label.substring(0, 16) + ".." : label;
        
        if (isEvent) {
          ctx.fillText((pos.node.engine || "").toUpperCase(), pos.x, pos.y);
          // Label below node
          ctx.fillStyle = "#94a3b8";
          ctx.font = "11px Inter";
          ctx.fillText(truncated, pos.x, pos.y + pos.radius + 14);
        } else {
          ctx.fillText("ENT", pos.x, pos.y);
          ctx.fillStyle = "#cbd5e1";
          ctx.font = "11px JetBrains Mono";
          ctx.fillText(truncated, pos.x, pos.y + pos.radius + 14);
        }
      });

      graphAnimationId = requestAnimationFrame(draw);
    }

    draw();
  }

  // =========================================================================
  // FILE INGESTION & SCENARIO LOADERS
  // =========================================================================

  function setupDropZone() {
    const dropZone = document.getElementById("dropZone");
    if (!dropZone) return;

    ["dragenter", "dragover"].forEach(event => {
      dropZone.addEventListener(event, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach(event => {
      dropZone.addEventListener(event, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove("dragover");
      });
    });

    dropZone.addEventListener("drop", (e) => {
      const files = e.dataTransfer.files;
      if (files.length > 0) window.handleFileSelect(files);
    });
  }

  window.handleFileSelect = async function (files) {
    if (!files || files.length === 0) return;
    const file = files[0];
    const forceType = document.getElementById("forceTypeSelect").value;

    const formData = new FormData();
    formData.append("file", file);

    const url = forceType ? `/api/analyze?force_type=${forceType}` : "/api/analyze";

    try {
      const btn = document.querySelector(".btn-browse");
      if (btn) btn.textContent = "Analyzing...";

      const res = await fetch(url, {
        method: "POST",
        body: formData
      });

      if (btn) btn.textContent = "Browse Files";

      if (res.ok) {
        const data = await res.json();
        alert(`Analysis Complete!\nClassified as: ${data.event.source_engine}\nEvent Type: ${data.event.event_type}\nAssigned to Campaign: ${data.campaign.campaign_id}`);
        await loadDashboardData();
        if (data.campaign && data.campaign.campaign_id) {
          window.selectCampaign(data.campaign.campaign_id);
        }
      } else {
        const err = await res.json();
        alert(`Ingestion Error: ${err.detail || 'Upload failed'}`);
      }
    } catch (err) {
      console.error("Upload error:", err);
      alert("Failed to connect to CyberGuard ingestion endpoint.");
    }
  };

  window.loadScenario = async function (scenarioId) {
    if (!scenarioId) return;
    try {
      const res = await fetch(`/api/load_scenario/${scenarioId}`, {
        method: "POST"
      });
      if (res.ok) {
        const data = await res.json();
        await loadDashboardData();
        if (data.campaign && data.campaign.campaign_id) {
          window.selectCampaign(data.campaign.campaign_id);
        }
      } else {
        alert("Failed to load demo scenario.");
      }
    } catch (err) {
      console.error("Scenario error:", err);
    }
  };

  window.executeResponse = async function () {
    if (!selectedCampaignId) return;
    const btn = document.getElementById("btnExecuteResponse");
    const statusBox = document.getElementById("responseStatusLog");

    btn.disabled = true;
    btn.innerHTML = `<span class="status-pulse"></span> Executing Containment...`;

    try {
      const res = await fetch(`/api/campaigns/${selectedCampaignId}/respond`, {
        method: "POST"
      });

      if (res.ok) {
        const data = await res.json();
        statusBox.style.display = "flex";
        statusBox.innerHTML = (data.execution_logs || []).map(log => `<div>${escapeHtml(log)}</div>`).join("");
        btn.innerHTML = `✓ Containment Verified`;
        setTimeout(() => {
          btn.disabled = false;
          btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon"><polygon points="5 3 19 12 5 21 5 3"/></svg> Execute Automated Containment`;
        }, 5000);
      }
    } catch (err) {
      console.error("Response execution failed:", err);
      btn.disabled = false;
      btn.textContent = "Execution Failed - Retry";
    }
  };

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

})();
