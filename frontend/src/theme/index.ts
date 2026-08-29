import type { ThemeConfig } from "antd";

/** LIMA 品牌主题 token：保持既有视觉身份，而非默认 AntD 风格。 */
export const limaBrandTokens = {
  colorPrimary: "#2457d6",
  colorInfo: "#2457d6",
  colorLink: "#2457d6",
  colorSuccess: "#1f8a4c",
  colorWarning: "#c2570a",
  colorError: "#c0392b",
  colorTextBase: "#1c2430",
  colorBgLayout: "#f4f7fb",
  borderRadius: 10,
  fontFamily:
    '"Inter", "PingFang SC", "Microsoft YaHei", system-ui, -apple-system, sans-serif',
} as const;

export const limaTheme: ThemeConfig = {
  token: limaBrandTokens,
  components: {
    Layout: { headerBg: "#ffffff", siderBg: "#ffffff" },
    Table: { headerBg: "#f7f9fd" },
  },
};
