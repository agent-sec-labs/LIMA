/// <reference types="@testing-library/jest-dom" />
import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// jsdom 无 matchMedia；antd 响应式组件依赖它。
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => undefined,
    removeListener: () => undefined,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    dispatchEvent: () => false,
  }),
});

// globals=false 时 RTL 不会自动清理渲染残留。
afterEach(() => {
  cleanup();
});
