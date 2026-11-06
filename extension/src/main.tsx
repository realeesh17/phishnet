import React from "react";
import ReactDOM from "react-dom/client";
import { FluentProvider, createLightTheme } from "@fluentui/react-components";
import App from "./App";
import "./style.css";

const brand = {
  10: "#061D1B",
  20: "#0A302D",
  30: "#0B4641",
  40: "#0B5D56",
  50: "#0F766E",
  60: "#16877E",
  70: "#30998F",
  80: "#4AABA1",
  90: "#65BDB3",
  100: "#81CEC5",
  110: "#9DDED6",
  120: "#B9EAE4",
  130: "#D0F1ED",
  140: "#E2F7F4",
  150: "#EFFBFA",
  160: "#F7FDFC",
};

const theme = {
  ...createLightTheme(brand),
  colorBrandForeground1: "#0F766E",
  colorBrandForeground2: "#0B5D56",
  colorBrandBackground: "#0F766E",
  colorBrandBackgroundHover: "#0B5D56",
  colorBrandBackgroundPressed: "#0A4641",
  colorNeutralBackground1: "#FFFFFF",
  colorNeutralBackground2: "#F4F7F9",
  colorNeutralForeground1: "#102A43",
  colorNeutralForeground2: "#52667A",
  colorNeutralStroke1: "#D8E1E8",
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <FluentProvider theme={theme}>
      <App />
    </FluentProvider>
  </React.StrictMode>,
);
