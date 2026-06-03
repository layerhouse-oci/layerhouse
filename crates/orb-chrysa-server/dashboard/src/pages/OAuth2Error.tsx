import { t } from "../lib/i18n";

export default function OAuth2Error() {
  return (
    <div class="oauth-error">
      <div class="card oauth-error-panel">
        <p class="eyebrow">{t("oauth2.errorEyebrow")}</p>
        <h1>{t("oauth2.stateErrorTitle")}</h1>
        <p>{t("oauth2.stateErrorDesc")}</p>
        <a class="btn btn-primary" href="/oauth2/start">
          {t("oauth2.restartLogin")}
        </a>
      </div>
    </div>
  );
}
