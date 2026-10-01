import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { UI_BASE } from "./api";
import App from "./App";
import "./theme.css";

const root = document.getElementById("root");
if (!root) throw new Error("no #root element");

// The router's base is where the panel mounted the interface, which may be an
// unguessable path rather than /admin. Deriving it means one build serves any
// path without being rebuilt.
createRoot(root).render(
  <StrictMode>
    <BrowserRouter basename={UI_BASE}>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
