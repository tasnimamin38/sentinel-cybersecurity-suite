import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import { resolveRoute } from "./routing/resolveroute.js";
import "./styles.css";
import "./motion.css";

const App = lazy(() => import("./app"));
const MarketingSite = lazy(() => import("./marketing/marketingsite"));
const NotFound = lazy(() => import("./routing/notfound"));

function RouteLoading() {
  return <div className="route-loading" role="status"><span className="loader-ring" /> Loading SENTINEL…</div>;
}

const route = resolveRoute(window.location.pathname);
const Page = route === "marketing" ? MarketingSite : route === "console" ? App : NotFound;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode><Suspense fallback={<RouteLoading />}><Page /></Suspense></React.StrictMode>,
);
