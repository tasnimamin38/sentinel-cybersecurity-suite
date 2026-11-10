export async function fetchPublicPlanCatalog(fetchImpl, apiBase, signal) {
  const response = await fetchImpl(`${apiBase}/api/v1/plans`, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) throw new Error("Plan details temporarily unavailable.");
  return response.json();
}
