"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { api } from "@/lib/api";

export function TaskDomainScopePreview({ value }: { value: string }) {
  const t = useTranslations("tasksPage.create");
  const [result, setResult] = React.useState<{ value: string; domains: string[]; error?: string } | null>(null);

  React.useEffect(() => {
    if (!value.trim()) return;
    let current = true;
    const timer = setTimeout(() => {
      api.previewTaskDomainScope(value).then(
        (preview) => {
          if (current) setResult({ value, domains: preview.domains });
        },
        (error: Error) => {
          if (current) setResult({ value, domains: [], error: error.message });
        },
      );
    }, 300);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [value]);

  if (!value.trim()) return <p className="text-muted-foreground text-xs">{t("domainHint")}</p>;
  if (result?.value !== value) return <p role="status">{t("domainChecking")}</p>;
  if (result.error) return <p role="alert">{result.error}</p>;
  return (
    <div role="status" className="text-muted-foreground text-xs">
      <p>{t("domainPreview", { count: result.domains.length })}</p>
      <p className="break-all">{result.domains.join(", ")}</p>
    </div>
  );
}
