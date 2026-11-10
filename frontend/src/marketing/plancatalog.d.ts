import type { PublicPlanCatalog } from "../shared/planTypes";
export function fetchPublicPlanCatalog(
  fetchImpl: typeof fetch,
  apiBase: string,
  signal?: AbortSignal,
): Promise<PublicPlanCatalog>;
