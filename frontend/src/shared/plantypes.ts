export type PublicPlan = {
  code: string;
  name: string;
  status: "active" | "preview";
  price: { amount_cents: number | null; currency: string; interval: string; display: string };
  default_for_new_workspaces?: boolean;
  purchasable: boolean;
  checkout_enabled: boolean;
  feature_codes?: string[];
  limits?: Record<string, unknown>;
  limits_enforced?: boolean;
  limit_enforcement_status?: string;
  capacity_preview?: Record<string, number> | null;
  planned_for?: string;
  notice?: string;
};

export type PublicPlanCatalog = {
  catalog_version: number;
  launch_mode: string;
  default_plan_code: string;
  billing_enabled: boolean;
  checkout_enabled: boolean;
  usage_limits_enforced: boolean;
  workspace_type: "personal" | "company" | null;
  feature_catalog?: {
    code: string;
    name: string;
    category: string;
    description: string;
    status: "available";
  }[];
  plans: PublicPlan[];
  notice: string;
};
