import { redirectToSignIn } from "../lib/api";
import { t } from "../lib/i18n";

export default function OAuth2Error() {
  return (
    <div class="oauth-error">
      <div class="card oauth-error-panel">
        <p class="eyebrow">{t("oauth2.errorEyebrow")}</p>
        <h1>{t("oauth2.stateErrorTitle")}</h1>
        <p>{t("oauth2.stateErrorDesc")}</p>
        <button type="button" class="btn btn-primary" onClick={redirectToSignIn}>
          {t("oauth2.restartLogin")}
        </button>
      </div>
    </div>
  );
}
