export function resolveApiBase(configuredBase, useSameOriginProxy) {
  if (useSameOriginProxy === "true") return "";
  return (configuredBase ?? "").replace(/\/+$/, "");
}
