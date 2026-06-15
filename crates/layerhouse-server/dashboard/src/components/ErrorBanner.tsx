import { t } from "../lib/i18n";

export default function ErrorBanner(props: {
  message: string;
  onRetry?: () => void;
  fullPage?: boolean;
}) {
  if (props.fullPage) {
    return (
      <div class="empty">
        <h3>{t("error.connectionLost")}</h3>
        <p style={{ color: "var(--color-error)", "margin-bottom": "1rem" }}>{props.message}</p>
        {props.onRetry && (
          <button class="btn btn-primary" onClick={props.onRetry}>
            {t("common.retry")}
          </button>
        )}
      </div>
    );
  }

  return (
    <div class="error-banner">
      <p>{props.message}</p>
      {props.onRetry && (
        <button class="btn" onClick={props.onRetry}>
          {t("common.retry")}
        </button>
      )}
    </div>
  );
}
