export type SentinelRoute = "marketing" | "console" | "not-found";
export function resolveRoute(pathname: string): SentinelRoute;
