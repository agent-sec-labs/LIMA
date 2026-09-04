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

// vitest 的 jsdom 环境里 AbortController/AbortSignal 来自 jsdom 域，而
// Request/Response 来自 Node undici——react-router v7 数据路由导航会用该
// signal 构造 Request，跨域实例校验必然抛 TypeError。本仓库路由树没有
// loader/action，导航 Request 从不真正发出，因此包装 Request：原生构造
// 失败时降级剥离 signal 重建（仅测试环境生效）。
type RequestCtor = new (input: RequestInfo | URL, init?: RequestInit) => Request;

const NativeRequest = globalThis.Request as RequestCtor;

function RealmSafeRequest(this: unknown, input: RequestInfo | URL, init?: RequestInit): Request {
  const attempt = init ?? {};
  try {
    return Reflect.construct(NativeRequest, [input, attempt], RealmSafeRequest as unknown as RequestCtor);
  } catch {
    return Reflect.construct(
      NativeRequest,
      [input, { ...attempt, signal: undefined }],
      RealmSafeRequest as unknown as RequestCtor,
    );
  }
}

// Reflect.construct 以 newTarget.prototype 作为实例原型；指回原生原型，
// 实例才能拿到 undici Request 的 url/method getter。
RealmSafeRequest.prototype = NativeRequest.prototype;

Object.defineProperty(globalThis, "Request", {
  configurable: true,
  writable: true,
  value: RealmSafeRequest,
});
