import { resolveApiBase } from "./resolveapibase.js";

export const API_BASE = resolveApiBase(import.meta.env.VITE_API_BASE_URL, import.meta.env.VITE_API_USE_PROXY);
