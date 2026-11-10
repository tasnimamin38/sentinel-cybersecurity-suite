export function resolveRoute(pathname) {
  if (pathname === "/") return "marketing";
  if (pathname === "/console" || pathname.startsWith("/console/")) return "console";
  return "not-found";
}
