const api = window.sniff4houndDesktop;
      const log = document.getElementById("log");
      const statusRow = document.getElementById("status-row");
      const localStart = document.getElementById("local-start");
      const remoteForm = document.getElementById("remote-form");
      const remoteConnect = document.getElementById("remote-connect");
      const remoteHost = document.getElementById("remote-host");
      const remotePort = document.getElementById("remote-port");
      const remoteCode = document.getElementById("remote-code");
      const remoteCa = document.getElementById("remote-ca");

      function setBusy(isBusy, message) {
        localStart.disabled = isBusy;
        remoteConnect.disabled = isBusy;
        statusRow.classList.toggle("active", Boolean(isBusy));
        if (message) log.textContent = message;
      }

      for (const button of document.querySelectorAll("[data-action]")) {
        button.addEventListener("click", () => {
          const action = button.getAttribute("data-action");
          if (api && typeof api[action] === "function") api[action]();
        });
      }

      if (api && typeof api.onRuntimeStatus === "function") {
        api.onRuntimeStatus((message) => {
          if (message) log.textContent = message;
        });
      }

      if (api && typeof api.getConnectionDefaults === "function") {
        api.getConnectionDefaults().then((defaults) => {
          remoteHost.value = defaults.host || "127.0.0.1";
          remotePort.value = defaults.port || defaults.localPort || "45678";
          if (defaults.mode === "remote") {
            remoteCode.focus();
          }
          if (defaults.requestPrivileges) startLocalSensor();
        });
      }

      async function startLocalSensor() {
        if (!api || typeof api.startLocal !== "function") return;
        setBusy(true, "Esperando autorización en el diálogo de autenticación...");
        try {
          const result = await api.startLocal();
          if (!result || result.ok !== true) {
            setBusy(false, (result && result.error) || "No se pudo iniciar el sensor local. Vuelve a intentarlo.");
          }
        } catch (error) {
          setBusy(false, error.message || "No se pudo iniciar el sensor local. Vuelve a intentarlo.");
        }
      }

      localStart.addEventListener("click", startLocalSensor);

      remoteForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!api || typeof api.connectRemote !== "function") return;
        setBusy(true, "Comprobando el sensor remoto...");
        try {
          const result = await api.connectRemote({
            host: remoteHost.value,
            port: remotePort.value,
            securityCode: remoteCode.value,
            caPem: remoteCa.value,
          });
          if (!result || result.ok !== true) {
            setBusy(false, (result && result.error) || "No se pudo conectar al sensor remoto. Revisa la dirección, el código y la CA.");
          }
        } catch (error) {
          setBusy(false, error.message || "No se pudo conectar al sensor remoto. Vuelve a intentarlo.");
        }
      });
