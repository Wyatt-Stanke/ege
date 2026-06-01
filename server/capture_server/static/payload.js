/* capture_server/static/payload.js
   Runs immediately on parse. Exercises a battery of TLS-connection-opening
   browser behaviors so the server captures representative fingerprint data. */
(async function () {
    "use strict";

    function setStatus(msg) {
        const el = document.getElementById("status");
        if (el) el.textContent = msg;
    }

    function getCookie(name) {
        const m = document.cookie.match(
            new RegExp("(?:^|; )" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)")
        );
        return m ? decodeURIComponent(m[1]) : null;
    }

    // Config: derive sibling origins from the page origin
    const CFG = {
        captureOrigin: location.origin,
        apiOrigin: location.origin.replace(/^(https?:\/\/)[^.]+/, "$1api"),
        cdnOrigin: location.origin.replace(/^(https?:\/\/)[^.]+/, "$1cdn"),
        wsOrigin: location.origin.replace(/^https/, "wss").replace(/^http/, "ws")
            .replace(/^(wss?:\/\/)[^.]+/, "$1ws"),
        probeTimeoutMs: 10000,
        sessionId: getCookie("__capture_sid") || null,
    };

    // Ensure we have a session cookie before starting probes
    if (!CFG.sessionId) {
        try {
            await fetch("/", { credentials: "include" });
            CFG.sessionId = getCookie("__capture_sid");
        } catch (_) { }
    }

    const sid = CFG.sessionId;
    const sidParam = sid ? "?sid=" + encodeURIComponent(sid) : "";

    const probesRun = [];
    const probesFailed = [];

    async function runProbe(name, fn) {
        setStatus("Probe: " + name);
        try {
            await Promise.race([
                fn(),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error("timeout")), CFG.probeTimeoutMs)
                ),
            ]);
            probesRun.push(name);
        } catch (_) {
            probesFailed.push(name);
        }
    }

    // --- Probes -----------------------------------------------------------

    await runProbe("xhr_same_origin", () =>
        new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open("GET", "/probe/xhr" + sidParam);
            xhr.onload = resolve;
            xhr.onerror = reject;
            xhr.send();
        })
    );

    await runProbe("fetch_simple_cors", () =>
        fetch(CFG.apiOrigin + "/probe/cors-simple" + sidParam, {
            credentials: "include",
        })
    );

    await runProbe("fetch_omit_creds", () =>
        fetch(CFG.apiOrigin + "/probe/cors-simple" + sidParam, {
            credentials: "omit",
        })
    );

    await runProbe("fetch_preflight", () =>
        fetch(CFG.apiOrigin + "/probe/cors-preflight" + sidParam, {
            method: "POST",
            headers: { "X-Capture-Probe": "1" },
            credentials: "include",
        })
    );

    await runProbe("post_form", () =>
        fetch("/probe/post-form" + sidParam, {
            method: "POST",
            body: new URLSearchParams({ probe: "post_form", sid: sid || "" }),
        })
    );

    await runProbe("post_multipart", () => {
        const fd = new FormData();
        fd.append("probe", "post_multipart");
        return fetch("/probe/post-multipart" + sidParam, { method: "POST", body: fd });
    });

    await runProbe("post_json", () =>
        fetch("/probe/post-json" + sidParam, {
            method: "POST",
            body: JSON.stringify({ probe: "post_json" }),
            headers: { "Content-Type": "application/json" },
        })
    );

    await runProbe("beacon", () => {
        navigator.sendBeacon("/probe/beacon" + sidParam, new Blob(["x"]));
        return Promise.resolve();
    });

    await runProbe("subresources", () =>
        new Promise((resolve) => {
            let done = 0;
            const check = () => { if (++done === 3) resolve(); };

            const img = document.createElement("img");
            img.onload = img.onerror = check;
            img.src = CFG.cdnOrigin + "/asset/image.png" + sidParam;
            document.body.appendChild(img);

            const script = document.createElement("script");
            script.onload = script.onerror = check;
            script.src = CFG.cdnOrigin + "/asset/script.js" + sidParam;
            document.body.appendChild(script);

            const link = document.createElement("link");
            link.rel = "stylesheet";
            link.onload = link.onerror = check;
            link.href = CFG.cdnOrigin + "/asset/style.css" + sidParam;
            document.head.appendChild(link);
        })
    );

    await runProbe("websocket", () =>
        new Promise((resolve) => {
            try {
                const ws = new WebSocket(CFG.wsOrigin + "/ws" + sidParam);
                ws.onopen = resolve;
                ws.onerror = resolve;
                ws.onclose = resolve;
            } catch (_) {
                resolve();
            }
        })
    );

    // --- Ground-truth report ---------------------------------------------

    setStatus("Collecting UA data…");

    let uaClientHints = null;
    if (navigator.userAgentData) {
        try {
            const hi = await navigator.userAgentData.getHighEntropyValues([
                "architecture",
                "bitness",
                "model",
                "platform",
                "platformVersion",
                "fullVersionList",
            ]);
            uaClientHints = {
                brands: navigator.userAgentData.brands,
                mobile: navigator.userAgentData.mobile,
                platform: hi.platform,
                platformVersion: hi.platformVersion,
                architecture: hi.architecture,
                bitness: hi.bitness,
                model: hi.model,
                fullVersionList: hi.fullVersionList,
            };
        } catch (_) {
            uaClientHints = {
                brands: navigator.userAgentData.brands,
                mobile: navigator.userAgentData.mobile,
            };
        }
    }

    const report = {
        session_id: sid,
        user_agent: navigator.userAgent,
        ua_client_hints: uaClientHints,
        navigator: {
            language: navigator.language,
            languages: Array.from(navigator.languages || []),
            vendor: navigator.vendor,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
        },
        probes_run: probesRun,
        probes_failed: probesFailed,
        client_time_iso: new Date().toISOString(),
    };

    setStatus("Sending report…");

    try {
        await fetch("/report" + sidParam, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(report),
            credentials: "include",
        });
        await fetch("/done" + sidParam, {
            method: "POST",
            credentials: "include",
        });
    } catch (_) { }

    setStatus("Done! Captures saved to captures/" + (sid || "(unknown session) "));
})();
