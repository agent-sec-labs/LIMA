import React from "react";
import { AppProviders } from "@/app/providers";
import { AppRouter, createAppRouter } from "@/router";
import type { AppRouterInstance } from "@/router";

/** 应用外壳：Provider 组合与路由出口。业务页面归属各 feature 目录。 */
export function App({ router }: { router?: AppRouterInstance }): React.JSX.Element {
  const resolved = router ?? createAppRouter();
  return (
    <AppProviders>
      <AppRouter router={resolved} />
    </AppProviders>
  );
}
