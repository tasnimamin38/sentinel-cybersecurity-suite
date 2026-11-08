export default {
  scheduled(_controller, env, ctx) {
    const apiUrl = env?.SENTINEL_API_URL;
    const workerSecret = env?.SENTINEL_WORKER_TICK_SECRET;

    if (
      typeof apiUrl !== "string" ||
      typeof workerSecret !== "string" ||
      workerSecret.length < 32
    ) {
      console.error("SENTINEL worker tick configuration is incomplete.");
      return;
    }

    let endpoint;
    try {
      const apiOrigin = new URL(apiUrl);
      if (
        apiOrigin.protocol !== "https:" ||
        apiOrigin.username ||
        apiOrigin.password ||
        apiOrigin.search ||
        apiOrigin.hash
      ) {
        console.error("SENTINEL worker tick requires a clean HTTPS API origin.");
        return;
      }
      endpoint = new URL("/internal/worker/tick", apiOrigin.origin);
    } catch {
      console.error("SENTINEL worker tick configuration has an invalid API URL.");
      return;
    }

    const request = fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sentinel-Worker-Secret": workerSecret,
      },
      body: "{}",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    })
      .then((response) => {
        if (!response.ok) {
          console.error("SENTINEL worker tick returned HTTP status", response.status);
        }
      })
      .catch((error) => {
        const errorName =
          error && typeof error === "object" && "name" in error ? error.name : "Error";
        console.error("SENTINEL worker tick request failed", errorName);
      });

    ctx.waitUntil(request);
  },
};
