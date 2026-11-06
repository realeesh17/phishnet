import React from "react";
import ReactDOM from "react-dom/client";
import { FluentProvider, createDarkTheme } from "@fluentui/react-components";
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
  ...createDarkTheme(brand),
  colorBrandForeground1: "#72DDB0",
  colorBrandForeground2: "#A1F0CB",
  colorBrandBackground: "#167B59",
  colorBrandBackgroundHover: "#1B9169",
  colorBrandBackgroundPressed: "#0E684A",
  colorNeutralBackground1: "#141D1B",
  colorNeutralBackground2: "#192421",
  colorNeutralBackground3: "#202E29",
  colorNeutralForeground1: "#F1F6F4",
  colorNeutralForeground2: "#A0B2AC",
  colorNeutralForeground3: "#83948E",
  colorNeutralStroke1: "#30413A",
  colorNeutralStroke2: "#28362F",
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <FluentProvider theme={theme}>
      <App />
    </FluentProvider>
  </React.StrictMode>,
);
