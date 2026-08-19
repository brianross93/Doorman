export function startDoormanBeacon(options = {}) {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return () => undefined;
  }

  const endpoint = options.endpoint || "/api/doorman/beacon";
  const initialDelayMs = Math.max(0, Number(options.initialDelayMs ?? 2500));
  const maxEvents = Math.max(1, Number(options.maxEvents ?? 10000));
  const startedAt = performance.now();
  const counts = { pointer: 0, keyboard: 0, scroll: 0 };
  let finalSent = false;

  const count = (key) => {
    counts[key] = Math.min(counts[key] + 1, maxEvents);
  };
  const pointer = () => count("pointer");
  const keyboard = () => count("keyboard");
  const scroll = () => count("scroll");

  window.addEventListener("pointerdown", pointer, { passive: true });
  window.addEventListener("keydown", keyboard, { passive: true });
  window.addEventListener("scroll", scroll, { passive: true });

  const payload = () =>
    JSON.stringify({
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
      pointerEvents: counts.pointer,
      keyboardEvents: counts.keyboard,
      scrollEvents: counts.scroll,
      webdriver: navigator.webdriver === true,
      visible: document.visibilityState === "visible",
    });

  const send = (final = false) => {
    if (final && finalSent) return;
    if (final) finalSent = true;
    const body = payload();
    if (final && navigator.sendBeacon) {
      navigator.sendBeacon(endpoint, new Blob([body], { type: "application/json" }));
      return;
    }
    void fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      credentials: "same-origin",
      keepalive: true,
    }).catch(() => undefined);
  };

  const timer = window.setTimeout(() => send(false), initialDelayMs);
  const finalSend = () => send(true);
  window.addEventListener("pagehide", finalSend);

  return () => {
    window.clearTimeout(timer);
    window.removeEventListener("pointerdown", pointer);
    window.removeEventListener("keydown", keyboard);
    window.removeEventListener("scroll", scroll);
    window.removeEventListener("pagehide", finalSend);
    send(true);
  };
}
