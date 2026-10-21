/* =========================================================================
   KyroMail - scripts côté client
   - menu mobile
   - fermeture des messages flash
   - confirmation avant suppression
   - compteur de caractères (rédaction)
   - notifications : compteur de non lus + alerte à l'arrivée d'un message
   ========================================================================= */
(function () {
  "use strict";

  var csrfMeta = document.querySelector('meta[name="csrf-token"]');
  var CSRF_TOKEN = csrfMeta ? csrfMeta.getAttribute("content") : "";

  /* ------------------------------------------------ Menu mobile --------- */
  var navToggle = document.getElementById("nav-toggle");
  var navOverlay = document.getElementById("nav-overlay");

  function closeNav() {
    document.body.classList.remove("nav-open");
    if (navToggle) navToggle.setAttribute("aria-expanded", "false");
    if (navOverlay) navOverlay.hidden = true;
  }

  function openNav() {
    document.body.classList.add("nav-open");
    if (navToggle) navToggle.setAttribute("aria-expanded", "true");
    if (navOverlay) navOverlay.hidden = false;
  }

  if (navToggle) {
    navToggle.addEventListener("click", function () {
      if (document.body.classList.contains("nav-open")) {
        closeNav();
      } else {
        openNav();
      }
    });
  }
  if (navOverlay) navOverlay.addEventListener("click", closeNav);

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeNav();
  });

  /* ------------------------------------------------ Messages flash ------ */
  var flashes = document.getElementById("flashes");
  if (flashes) {
    Array.prototype.forEach.call(flashes.querySelectorAll(".flash-close"), function (button) {
      button.addEventListener("click", function () {
        var flash = button.closest(".flash");
        if (flash) flash.remove();
        if (flashes && !flashes.querySelector(".flash")) flashes.remove();
      });
    });

    // Les messages de succès disparaissent seuls au bout de 6 secondes.
    window.setTimeout(function () {
      Array.prototype.forEach.call(flashes.querySelectorAll(".flash--success"), function (el) {
        el.style.transition = "opacity .4s ease";
        el.style.opacity = "0";
        window.setTimeout(function () { el.remove(); }, 400);
      });
    }, 6000);
  }

  /* --------------------------------------- Confirmation avant POST ------ */
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });

  /* ------------------------------------------- Compteur de caractères --- */
  function updateCount(input) {
    var target = document.getElementById(input.getAttribute("data-target"));
    if (!target) return;
    var max = parseInt(input.getAttribute("data-max"), 10) || 0;
    input.textContent = target.value.length + " / " + max;
  }

  var counters = document.querySelectorAll(".char-count");
  if (counters.length) {
    Array.prototype.forEach.call(counters, function (counter) {
      var target = document.getElementById(counter.getAttribute("data-target"));
      if (!target) return;
      updateCount(counter);
      target.addEventListener("input", function () { updateCount(counter); });
    });
  }

  /* --------------------------------------------- Notifications local ---- */
  var enableBtn = document.getElementById("enable-notifications");
  var statusEl = document.getElementById("notifications-status");

  function renderStatus(text) {
    if (statusEl) statusEl.textContent = text;
  }

  if (enableBtn) {
    if (!("Notification" in window)) {
      enableBtn.disabled = true;
      renderStatus("Ce navigateur ne prend pas en charge les notifications.");
    } else if (Notification.permission === "granted") {
      enableBtn.disabled = true;
      renderStatus("Notifications déjà activées.");
    } else if (Notification.permission === "denied") {
      enableBtn.disabled = true;
      renderStatus("Notifications bloquées dans les réglages du navigateur.");
    }

    enableBtn.addEventListener("click", function () {
      if (!("Notification" in window)) return;
      Notification.requestPermission().then(function (permission) {
        if (permission === "granted") {
          enableBtn.disabled = true;
          renderStatus("Notifications activées.");
          notify("KyroMail", "Vous serez prévenu de l'arrivée de nouveaux messages.");
        } else {
          renderStatus("Autorisation refusée.");
        }
      });
    });
  }

  function notify(title, body) {
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    try {
      new Notification(title, { body: body, tag: "kyromail-message" });
    } catch (error) {
      // Certains navigateurs exigent une icône : on ignore proprement.
    }
  }

  function showToast(text) {
    var existing = document.querySelector(".toast");
    if (existing) existing.remove();

    var toast = document.createElement("div");
    toast.className = "toast";
    toast.setAttribute("role", "status");
    toast.textContent = text;
    document.body.appendChild(toast);
    window.setTimeout(function () { toast.remove(); }, 6000);
  }

  /* ------------------------------------- Interrogation du serveur ------- */
  var topbarPill = document.getElementById("topbar-unread");
  var topbarCount = document.getElementById("topbar-unread-count");
  var sidebarBadge = document.getElementById("sidebar-unread");
  var knownUnread = null;
  var pollTimer = null;

  function applyUnread(count) {
    if (topbarCount) topbarCount.textContent = String(count);
    if (topbarPill) topbarPill.hidden = count === 0;
    if (sidebarBadge) {
      sidebarBadge.textContent = String(count);
      sidebarBadge.hidden = count === 0;
    }

    if (knownUnread !== null && count > knownUnread) {
      var delta = count - knownUnread;
      showToast(delta === 1 ? "1 nouveau message reçu." : delta + " nouveaux messages reçus.");
      notify("KyroMail", delta === 1 ? "Vous avez reçu un nouveau message." :
        "Vous avez reçu " + delta + " nouveaux messages.");
    }
    knownUnread = count;
  }

  function pollUnread() {
    fetch("/api/unread-count", {
      method: "GET",
      credentials: "same-origin",
      headers: { "X-Requested-With": "fetch" }
    })
      .then(function (response) {
        if (!response.ok) throw new Error("statut " + response.status);
        return response.json();
      })
      .then(function (data) {
        if (typeof data.unread === "number") applyUnread(data.unread);
      })
      .catch(function () {
        // Réseau coupé ou session expirée : on réessaiera au prochain cycle.
      });
  }

  if (document.body.classList.contains("is-app")) {
    var initial = document.getElementById("topbar-unread-count");
    knownUnread = initial ? parseInt(initial.textContent, 10) || 0 : 0;
    pollTimer = window.setInterval(pollUnread, 20000);
    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) pollUnread();
    });
  }

  /* ------------------------------------------- Activer/désactiver ------- */
  window.KyroMail = {
    csrfToken: CSRF_TOKEN,
    pollUnread: pollUnread,
    stopPolling: function () {
      if (pollTimer) window.clearInterval(pollTimer);
    }
  };
})();
