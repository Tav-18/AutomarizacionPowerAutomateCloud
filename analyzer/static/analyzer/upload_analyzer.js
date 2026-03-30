(function () {
  const input = document.getElementById("id_solution_zip");
  const projectInput = document.getElementById("id_project_id");
  const uploader = document.getElementById("uploader");
  const fileUi = document.getElementById("fileUi");
  const orbBtn = document.getElementById("orbBtn");
  const filePill = document.getElementById("filePill");
  const fileName = document.getElementById("fileName");
  const fileSize = document.getElementById("fileSize");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const clearBtn = document.getElementById("clearBtn");
  const overlay = document.getElementById("overlay");
  const overlayMessage = document.getElementById("overlayMessage");
  const progress = document.getElementById("progress");
  const fileHint = document.getElementById("fileHint");
const uploadForm = document.getElementById("uploadForm");
const cleanUploadUrl = uploadForm ? uploadForm.dataset.uploadUrl : "/";
const fileError = document.getElementById("fileError");
const projectError = document.getElementById("projectError");
const flowSummaryCard = document.getElementById("flowSummaryCard");

  const selectedJsonsContainer = document.getElementById("selectedJsonsContainer");
  const selectedFlowsSummary = document.getElementById("selectedFlowsSummary");
  const applyFlowSelectionBtn = document.getElementById("applyFlowSelectionBtn");
  const pickerError = document.getElementById("pickerError");
  const selectAllBtn = document.getElementById("selectAllBtn");
  const clearAllBtn = document.getElementById("clearAllBtn");
  const checkboxes = Array.from(document.querySelectorAll(".json-checkbox"));
  const modalTriggers = document.querySelectorAll("[data-modal-open]");
  const modals = document.querySelectorAll(".info-modal");

  const isUploadPage = !!(uploadForm && input && uploader);

  function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;

    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    modal.classList.add("is-open");
    document.body.classList.add("modal-open");
  }

  function closeModal(modal) {
    if (!modal) return;

    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    modal.hidden = true;
    document.body.classList.remove("modal-open");
  }

  modalTriggers.forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      openModal(this.dataset.modalOpen);
    });
  });

modals.forEach(function (modal) {
  modal.addEventListener("click", function (event) {
    if (event.target === modal || event.target.matches("[data-modal-close]")) {
      closeModal(modal);
    }
  });
});

document.addEventListener("keydown", function (event) {
  if (event.key !== "Escape") return;

  document.querySelectorAll(".info-modal.is-open").forEach(function (modal) {
    closeModal(modal);
  });
});

/* ==========================================================================
   Findings table pagination
   ========================================================================== */
(function initFindingsPagination() {
  const table = document.getElementById("findingDetailsTable");
  const pageSizeSelect = document.getElementById("findingsPageSize");
  const pagination = document.getElementById("findingsPagination");
  const meta = document.getElementById("findingsTableMeta");

  if (!table || !pageSizeSelect || !pagination || !meta) {
    return;
  }

  const body = table.querySelector("tbody");
  if (!body) return;

  const allRows = Array.from(body.querySelectorAll("tr")).filter((row) => {
    return !row.querySelector(".empty-state-cell");
  });

  if (!allRows.length) {
    meta.textContent = "Showing 0 to 0 of 0 findings";
    pagination.hidden = true;
    return;
  }

  let currentPage = 1;
  let pageSize = Number(pageSizeSelect.value) || 10;

  function getTotalPages() {
    return Math.max(1, Math.ceil(allRows.length / pageSize));
  }

  function updateMeta(startIndex, endIndex) {
    meta.textContent = `Showing ${startIndex} to ${endIndex} of ${allRows.length} incidents`;
  }

  function createButton(label, onClick, options = {}) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "table-page-btn";
    btn.textContent = label;

    if (options.active) {
      btn.classList.add("is-active");
    }

    if (options.disabled) {
      btn.disabled = true;
    }

    btn.addEventListener("click", onClick);
    return btn;
  }

function renderPagination() {
  const totalPages = getTotalPages();
  pagination.innerHTML = "";

  if (totalPages <= 1) {
    pagination.hidden = true;
    return;
  }

  pagination.hidden = false;

  const firstBtn = createButton(
    "<<",
    function () {
      if (currentPage > 1) {
        currentPage = 1;
        renderRows();
      }
    },
    { disabled: currentPage === 1 }
  );
  firstBtn.setAttribute("aria-label", "Go to first page");
  firstBtn.title = "First page";

  const prevBtn = createButton(
    "<",
    function () {
      if (currentPage > 1) {
        currentPage -= 1;
        renderRows();
      }
    },
    { disabled: currentPage === 1 }
  );
  prevBtn.setAttribute("aria-label", "Go to previous page");
  prevBtn.title = "Previous page";

  const pageIndicator = document.createElement("span");
  pageIndicator.className = "table-page-indicator";
  pageIndicator.textContent = String(currentPage);
  pageIndicator.setAttribute("aria-label", `Current page ${currentPage} of ${totalPages}`);

  const nextBtn = createButton(
    ">",
    function () {
      if (currentPage < totalPages) {
        currentPage += 1;
        renderRows();
      }
    },
    { disabled: currentPage === totalPages }
  );
  nextBtn.setAttribute("aria-label", "Go to next page");
  nextBtn.title = "Next page";

  const lastBtn = createButton(
    ">>",
    function () {
      if (currentPage < totalPages) {
        currentPage = totalPages;
        renderRows();
      }
    },
    { disabled: currentPage === totalPages }
  );
  lastBtn.setAttribute("aria-label", "Go to last page");
  lastBtn.title = "Last page";

  pagination.appendChild(firstBtn);
  pagination.appendChild(prevBtn);
  pagination.appendChild(pageIndicator);
  pagination.appendChild(nextBtn);
  pagination.appendChild(lastBtn);
}
  function renderRows() {
    const totalPages = getTotalPages();

    if (currentPage > totalPages) {
      currentPage = totalPages;
    }

    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;

    allRows.forEach((row, index) => {
      row.style.display = index >= start && index < end ? "" : "none";
    });

    const visibleStart = allRows.length ? start + 1 : 0;
    const visibleEnd = Math.min(end, allRows.length);

    updateMeta(visibleStart, visibleEnd);
    renderPagination();
  }

  pageSizeSelect.addEventListener("change", function () {
    pageSize = Number(this.value) || 10;
    currentPage = 1;
    renderRows();
  });

  renderRows();
})();

if (!isUploadPage) {
  return;
}
  const hasPickerState = !!selectedJsonsContainer;
  const hasPersistentUpload = !!(filePill && filePill.dataset.persistent === "true");

  function fmtBytes(bytes) {
    if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return "";

    const units = ["B", "KB", "MB", "GB"];
    let value = bytes;
    let index = 0;

    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }

    return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function validateZip(file) {
    return !!file && typeof file.name === "string" && file.name.toLowerCase().endsWith(".zip");
  }

  function hasProjectId() {
    return !!projectInput && projectInput.value.trim().length > 0;
  }

  function getSelectedFile() {
    return input.files && input.files.length ? input.files[0] : null;
  }

  function getSelectedFlowCount() {
    if (!hasPickerState) return 0;
    return checkboxes.filter((cb) => cb.checked).length;
  }

  function showFileError(show, message) {
    if (!fileError) return;

    if (message) {
      fileError.textContent = message;
    }

    fileError.hidden = !show;
  }

  function showProjectError(show, message) {
    if (!projectError) return;

    if (message) {
      projectError.textContent = message;
    }

    projectError.hidden = !show;
  }

  function showPickerError(show, message) {
    if (!pickerError) return;

    if (message) {
      pickerError.textContent = message;
    }

    pickerError.hidden = !show;
  }

  function clearDisplayedFileInfo(force = false) {
    if (hasPersistentUpload && !force) {
      if (filePill) filePill.hidden = false;
      if (fileHint) fileHint.textContent = "Your file is ready to analyze";
      return;
    }

    if (fileName) fileName.textContent = "—";
    if (fileSize) fileSize.textContent = "—";
    if (filePill) filePill.hidden = true;

    if (fileHint) {
      fileHint.textContent = "Drag your .zip file here or click to browse";
    }
  }

  function syncAnalyzeState() {
    let canAnalyze = false;

    if (hasPickerState) {
      canAnalyze = hasProjectId() && getSelectedFlowCount() > 0;
    } else {
      const file = getSelectedFile();
      canAnalyze = validateZip(file);
    }

    if (analyzeBtn) {
      analyzeBtn.disabled = !canAnalyze;
    }
  }

  function resetFileUI(force = false) {
    clearDisplayedFileInfo(force);
    showFileError(false);
    syncAnalyzeState();
  }

  function setFileUI(file) {
    if (!file || !validateZip(file)) {
      clearDisplayedFileInfo();
      showFileError(true, "Please select a valid .zip file.");
      syncAnalyzeState();
      return;
    }

    if (fileName) fileName.textContent = file.name;
    if (fileSize) fileSize.textContent = fmtBytes(file.size);
    if (filePill) filePill.hidden = false;

    if (fileHint) {
      fileHint.textContent = "Your file is ready to analyze";
    }

    showFileError(false);
    syncAnalyzeState();
  }

  function openPicker() {
    input.click();
  }

  function handleInvalidZip() {
    input.value = "";

    if (filePill) {
      filePill.removeAttribute("data-persistent");
    }

    clearDisplayedFileInfo(true);
    showFileError(true, "Please select a valid .zip file.");
    syncAnalyzeState();
  }

  function discoverFlowsImmediately() {
    if (hasPickerState) return;

    const file = getSelectedFile();
    if (!validateZip(file)) return;

    // Descubrimiento automático de flujos.
    // No valida Project ID en esta fase.
    uploadForm.submit();
  }

  function updateSelectedCount() {
    const total = getSelectedFlowCount();

    if (selectedFlowsSummary) {
      selectedFlowsSummary.textContent = String(total);
    }

    if (total > 0) {
      showPickerError(false);
    }

    syncAnalyzeState();
  }

  function syncHiddenSelectedInputs() {
    if (!selectedJsonsContainer) return;

    selectedJsonsContainer.innerHTML = "";

    checkboxes
      .filter((cb) => cb.checked)
      .forEach((cb) => {
        const hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "selected_jsons";
        hidden.value = cb.value;
        selectedJsonsContainer.appendChild(hidden);
      });
  }

  function showAnalyzeOverlay(message) {
    if (overlay) {
      overlay.classList.add("show");
      overlay.setAttribute("aria-hidden", "false");
    }

    if (overlayMessage) {
      overlayMessage.textContent = message;
    }

    if (progress) {
      let percent = 5;
      progress.style.width = percent + "%";

      const timer = window.setInterval(function () {
        percent = Math.min(95, percent + 7);
        progress.style.width = percent + "%";
      }, 250);

      window.setTimeout(function () {
        window.clearInterval(timer);
      }, 6000);
    }
  }

  if (fileUi) {
    fileUi.addEventListener("click", function (event) {
      event.preventDefault();
      openPicker();
    });
  }

  if (orbBtn) {
    orbBtn.addEventListener("click", function (event) {
      event.preventDefault();
      openPicker();
    });
  }

  input.addEventListener("change", function () {
    const file = getSelectedFile();

    if (!file) {
      resetFileUI();
      return;
    }

    if (!validateZip(file)) {
      handleInvalidZip();
      return;
    }

    setFileUI(file);

    // En cuanto se selecciona el ZIP, descubrimos los flujos automáticamente.
    if (!hasPickerState) {
      window.setTimeout(function () {
        discoverFlowsImmediately();
      }, 120);
    }
  });

if (clearBtn) {
  clearBtn.setAttribute("type", "button");
  clearBtn.addEventListener("click", function (event) {
    event.preventDefault();
    event.stopPropagation();

    if (filePill) {
      filePill.removeAttribute("data-persistent");
    }

    input.value = "";

    showFileError(false);
    showProjectError(false);
    showPickerError(false);

    if (selectedJsonsContainer) {
      selectedJsonsContainer.innerHTML = "";
    }

    if (flowSummaryCard) {
      flowSummaryCard.hidden = true;
    }

    clearDisplayedFileInfo(true);

    if (analyzeBtn) {
      analyzeBtn.disabled = true;
    }

    if (hasPickerState) {
      window.location.href = cleanUploadUrl;
      return;
    }

    resetFileUI(true);
  });
}

  if (projectInput) {
    projectInput.addEventListener("input", function () {
      if (hasProjectId()) {
        showProjectError(false);
      }

      syncAnalyzeState();
    });

    projectInput.addEventListener("blur", function () {
      if (hasPickerState && !hasProjectId()) {
        showProjectError(true, "Please enter a Project ID before continuing.");
      }
    });
  }

  ["dragenter", "dragover"].forEach(function (evt) {
    uploader.addEventListener(evt, function (event) {
      event.preventDefault();
      event.stopPropagation();
      uploader.classList.add("is-dragover");
    });
  });

  ["dragleave", "drop"].forEach(function (evt) {
    uploader.addEventListener(evt, function (event) {
      event.preventDefault();
      event.stopPropagation();
      uploader.classList.remove("is-dragover");
    });
  });

  uploader.addEventListener("drop", function (event) {
    const dataTransfer = event.dataTransfer;

    if (!dataTransfer || !dataTransfer.files || dataTransfer.files.length === 0) {
      return;
    }

    const file = dataTransfer.files[0];

    if (!validateZip(file)) {
      handleInvalidZip();
      return;
    }

    try {
      input.files = dataTransfer.files;
      setFileUI(file);

      if (!hasPickerState) {
        window.setTimeout(function () {
          discoverFlowsImmediately();
        }, 120);
      }
    } catch (error) {
      setFileUI(file);
    }
  });

  if (selectAllBtn) {
    selectAllBtn.addEventListener("click", function () {
      checkboxes.forEach((cb) => {
        cb.checked = true;
      });
      updateSelectedCount();
    });
  }

  if (clearAllBtn) {
    clearAllBtn.addEventListener("click", function () {
      checkboxes.forEach((cb) => {
        cb.checked = false;
      });
      updateSelectedCount();
    });
  }

  checkboxes.forEach((checkbox) => {
    checkbox.addEventListener("change", updateSelectedCount);
  });

  if (applyFlowSelectionBtn) {
    applyFlowSelectionBtn.addEventListener("click", function () {
      const total = getSelectedFlowCount();

      if (total === 0) {
        showPickerError(true, "Select at least one flow.");
        return;
      }

      syncHiddenSelectedInputs();
      updateSelectedCount();

      document.querySelectorAll(".info-modal.is-open").forEach(function (modal) {
        closeModal(modal);
      });
    });
  }

  uploadForm.addEventListener("submit", function (event) {
    // Si todavía no existe el estado del picker, este submit es el de descubrimiento automático
    // o el submit manual para cargar el ZIP.
    if (!hasPickerState) {
      const file = getSelectedFile();

      if (!validateZip(file)) {
        event.preventDefault();
        showFileError(true, "Please select a valid .zip file.");
        syncAnalyzeState();
        return;
      }

      showFileError(false);
      return;
    }

    // Si ya existen flujos descubiertos, este submit es el análisis final.
    const projectOk = hasProjectId();
    const selectedCount = getSelectedFlowCount();

    if (!projectOk) {
      event.preventDefault();
      showProjectError(true, "Please enter a Project ID before continuing.");
    } else {
      showProjectError(false);
    }

    if (selectedCount === 0) {
      event.preventDefault();
      showPickerError(true, "Select at least one flow.");
    } else {
      showPickerError(false);
    }

    if (!projectOk || selectedCount === 0) {
      syncAnalyzeState();
      return;
    }

    syncHiddenSelectedInputs();
    showAnalyzeOverlay("Analyzing selected flows and preparing the Excel report…");
  });

  if (hasPersistentUpload) {
    if (filePill) filePill.hidden = false;
    if (fileHint) fileHint.textContent = "Your file is ready to analyze";
    showFileError(false);
  } else {
    resetFileUI();
  }

  showProjectError(false);

  if (hasPickerState) {
    syncHiddenSelectedInputs();
    updateSelectedCount();
  } else {
    syncAnalyzeState();
  }
}

)();

(function initPulseCanvas() {
  var canvas = document.getElementById("pulse-canvas");
  if (!canvas) return;

  var host = canvas.closest("[data-compliance-theme]") || document.querySelector(".metric-card--core");
  var theme = host && host.dataset && host.dataset.complianceTheme
    ? host.dataset.complianceTheme
    : ((host && host.className) || "");

  var state = "green";
  ["green", "yellow", "orange", "red", "rejected"].forEach(function (s) {
    if (theme.indexOf(s) !== -1) state = s;
  });

var CONFIGS = {
  green:    { amp: 29, noise: 2.2, period: 82, speed: 0.38, color: "#22c55e" },
  yellow:   { amp: 23, noise: 1.6, period: 66, speed: 0.55, color: "#eab308" },
  orange:   { amp: 17, noise: 1.0, period: 54, speed: 0.70, color: "#f97316" },
  red:      { amp: 11, noise: 0.5, period: 44, speed: 0.88, color: "#ef4444" },
  rejected: { amp: 0,  noise: 0.0, period: 80, speed: 0.18, color: "#9ca3af" }
};

  var cfg = CONFIGS[state] || CONFIGS.green;
  var isRejected = state === "rejected";

  var dpr = window.devicePixelRatio || 1;
  var ctx, W, H, offset = 0, startTime = performance.now();

  function resize() {
    var rect = canvas.getBoundingClientRect();
    canvas.width = Math.max(1, Math.floor(rect.width * dpr));
    canvas.height = Math.max(1, Math.floor(rect.height * dpr));
    ctx = canvas.getContext("2d");
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    W = rect.width;
    H = rect.height;
  }

  function makePoints() {
  var pts = [];
  var base = 29;

  // Perfil tipo ECG con picos más triangulares
  // t va de 0 a 1 dentro de cada periodo
  function heartbeatShape(t, amp) {
    if (t < 0.12) {
      return 0; // línea base
    } else if (t < 0.18) {
      // pequeña subida previa
      return -amp * ((t - 0.12) / 0.06) * 0.18;
    } else if (t < 0.22) {
      // regreso a base
      return -amp * (1 - (t - 0.18) / 0.04) * 0.18;
    } else if (t < 0.28) {
  return -amp * ((t - 0.22) / 0.06);
} else if (t < 0.33) {
  return -amp + (amp * 1.65) * ((t - 0.28) / 0.05);
} else if (t < 0.44) {
      // rebote de recuperación
      return amp * 0.55 - (amp * 0.70) * ((t - 0.36) / 0.08);
    } else if (t < 0.58) {
      // estabilización
      return -amp * 0.15 * (1 - (t - 0.44) / 0.14);
    } else {
      return 0; // línea base
    }
  }

  for (var x = 0; x <= 380; x++) {
    if (isRejected) {
      pts.push(base);
      continue;
    }

    var t = (x % cfg.period) / cfg.period;
    var y = base + heartbeatShape(t, cfg.amp);

    // un poco de microvariación para que no se vea demasiado rígido
    y += (Math.random() - 0.5) * cfg.noise * 0.35;

    pts.push(y);
  }

  return pts;
}

  function drawNormal() {
    var pts = makePoints();
    var total = pts.length;

    ctx.clearRect(0, 0, W, H);
    ctx.strokeStyle = cfg.color;
    ctx.lineWidth = 1.6;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.shadowColor = cfg.color;
    ctx.shadowBlur = 6;

    ctx.beginPath();

for (var i = 0; i < total; i++) {
  var idx = Math.floor(i + offset) % total;
  var x = (i / (total - 1)) * W;
  var y = (pts[idx] / 58) * H;

  if (i === 0) {
    ctx.moveTo(x, y);
  } else {
    var prevIdx = Math.floor(i - 1 + offset) % total;
    var prevX = ((i - 1) / (total - 1)) * W;
    var prevY = (pts[prevIdx] / 58) * H;

    var cx = (prevX + x) / 2;
    var cy = (prevY + y) / 2;

    ctx.quadraticCurveTo(prevX, prevY, cx, cy);
  }
}

ctx.stroke();

    var dotI = Math.floor(total * 0.97);
    var dotIdx = (dotI + Math.floor(offset)) % total;
    var dotX = (dotI / (total - 1)) * W;
    var dotY = (pts[dotIdx] / 58) * H;

    ctx.beginPath();
    ctx.arc(dotX, dotY, 2.6, 0, Math.PI * 2);
    ctx.fillStyle = cfg.color;
    ctx.shadowBlur = 10;
    ctx.fill();

    offset = (offset + cfg.speed) % total;
  }

  function drawRejected(now) {
    var t = (now - startTime) / 1000;
    var y = H * 0.5;

    ctx.clearRect(0, 0, W, H);

    // línea plana
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(W, y);
    ctx.strokeStyle = "rgba(127,29,29,0.40)";
    ctx.lineWidth = 1.5;
    ctx.shadowBlur = 0;
    ctx.stroke();

    // punto viajando de izquierda a derecha
    var progress = (t * 0.32) % 1; // velocidad
    var dotX = progress * W;

    // rastro
    var trail = ctx.createLinearGradient(dotX - 46, 0, dotX, 0);
    trail.addColorStop(0, "rgba(185,28,28,0)");
    trail.addColorStop(1, "rgba(185,28,28,0.30)");
    ctx.beginPath();
    ctx.moveTo(Math.max(0, dotX - 46), y);
    ctx.lineTo(dotX, y);
    ctx.strokeStyle = trail;
    ctx.lineWidth = 2;
    ctx.stroke();

    // punto principal
    ctx.beginPath();
    ctx.arc(dotX, y, 3.2, 0, Math.PI * 2);
    ctx.fillStyle = "#dc2626";
    ctx.shadowColor = "rgba(220,38,38,0.75)";
    ctx.shadowBlur = 12;
    ctx.fill();

    // pequeño destello al reiniciar
    if (progress < 0.03) {
      ctx.fillStyle = "rgba(255,255,255,0.06)";
      ctx.fillRect(0, 0, W, H);
    }
  }

  function animate(now) {
    if (!ctx) return;
    if (isRejected) drawRejected(now);
    else drawNormal();
    requestAnimationFrame(animate);
  }

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(animate);
})();