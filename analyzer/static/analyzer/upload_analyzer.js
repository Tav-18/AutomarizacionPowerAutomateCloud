(function () {
  const input = document.getElementById("id_solution_zip");
  const projectInput = document.getElementById("id_project_id");
  const uploader = document.getElementById("uploader");
  const fileUi = document.getElementById("fileUi");
  const orbBtn = document.getElementById("orbBtn");
  const filePill = document.getElementById("filePill");
  const fileName = document.getElementById("fileName");
  const fileSize = document.getElementById("fileSize");
  const clearBtn = document.getElementById("clearBtn");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const overlay = document.getElementById("overlay");
  const overlayMessage = document.getElementById("overlayMessage");
  const progress = document.getElementById("progress");
  const fileHint = document.getElementById("fileHint");
  const uploadForm = document.getElementById("uploadForm");
  const fileError = document.getElementById("fileError");
  const projectError = document.getElementById("projectError");

  if (!input || !uploader || !uploadForm) {
    return;
  }

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

  function clearDisplayedFileInfo() {
    if (fileName) fileName.textContent = "—";
    if (fileSize) fileSize.textContent = "—";
    if (filePill) filePill.hidden = true;

    if (fileHint) {
      fileHint.textContent = "Arrastra y suelta tu solution.zip aquí o haz clic para buscar";
    }
  }

  function syncAnalyzeState() {
    const file = getSelectedFile();
    const canAnalyze = validateZip(file) && hasProjectId();

    if (analyzeBtn) {
      analyzeBtn.disabled = !canAnalyze;
    }
  }

  function resetFileUI() {
    clearDisplayedFileInfo();
    showFileError(false);
    syncAnalyzeState();
  }

  function setFileUI(file) {
    if (!file || !validateZip(file)) {
      clearDisplayedFileInfo();
      showFileError(true, "Selecciona un archivo .zip válido.");
      syncAnalyzeState();
      return;
    }

    if (fileName) fileName.textContent = file.name;
    if (fileSize) fileSize.textContent = fmtBytes(file.size);
    if (filePill) filePill.hidden = false;

    if (fileHint) {
      fileHint.textContent = "Archivo listo para analizar";
    }

    showFileError(false);
    syncAnalyzeState();
  }

  function openPicker() {
    input.click();
  }

  function handleInvalidZip() {
    input.value = "";
    clearDisplayedFileInfo();
    showFileError(true, "Selecciona un archivo .zip válido.");
    syncAnalyzeState();
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
  });

  if (clearBtn) {
    clearBtn.setAttribute("type", "button");
    clearBtn.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();

      input.value = "";
      resetFileUI();
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
      if (!hasProjectId()) {
        showProjectError(true, "Ingresa un Project ID antes de continuar.");
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
    } catch (error) {
      // En algunos navegadores esta asignación puede fallar.
      // En ese caso solo reflejamos la UI, pero el usuario tendría que seleccionar manualmente el archivo.
      setFileUI(file);
      return;
    }

    setFileUI(file);
  });

  uploadForm.addEventListener("submit", function (event) {
    const file = getSelectedFile();
    const zipOk = validateZip(file);
    const projectOk = hasProjectId();

    if (!zipOk) {
      event.preventDefault();
      showFileError(true, "Selecciona un archivo .zip válido.");
    } else {
      showFileError(false);
    }

    if (!projectOk) {
      event.preventDefault();
      showProjectError(true, "Ingresa un Project ID antes de continuar.");
    } else {
      showProjectError(false);
    }

    if (!zipOk || !projectOk) {
      syncAnalyzeState();
      return;
    }

    if (overlay) {
      overlay.classList.add("show");
      overlay.setAttribute("aria-hidden", "false");
    }

    if (overlayMessage) {
      overlayMessage.textContent = "Aplicando reglas y preparando el reporte de Excel…";
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
  });

  resetFileUI();
  showProjectError(false);
  syncAnalyzeState();
})();