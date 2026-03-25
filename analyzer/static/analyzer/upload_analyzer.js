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
  const fileError = document.getElementById("fileError");
  const projectError = document.getElementById("projectError");

  const selectedJsonsContainer = document.getElementById("selectedJsonsContainer");
  const selectedFlowsSummary = document.getElementById("selectedFlowsSummary");
  const applyFlowSelectionBtn = document.getElementById("applyFlowSelectionBtn");
  const pickerError = document.getElementById("pickerError");
  const selectAllBtn = document.getElementById("selectAllBtn");
  const clearAllBtn = document.getElementById("clearAllBtn");
  const checkboxes = Array.from(document.querySelectorAll(".json-checkbox"));
  const modalTriggers = document.querySelectorAll("[data-modal-open]");
  const modals = document.querySelectorAll(".info-modal");

  if (!uploadForm || !input || !uploader) {
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
      // Si el navegador no permite asignar input.files,
      // solo actualizamos la UI localmente.
      setFileUI(file);
    }
  });

  modalTriggers.forEach(function (trigger) {
    trigger.addEventListener("click", function () {
      openModal(this.dataset.modalOpen);
    });
  });

  modals.forEach(function (modal) {
    modal.addEventListener("click", function (event) {
      if (event.target.matches("[data-modal-close]")) {
        closeModal(modal);
      }
    });
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

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;

    document.querySelectorAll(".info-modal.is-open").forEach(function (modal) {
      closeModal(modal);
    });
  });

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
})();