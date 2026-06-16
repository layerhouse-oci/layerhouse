import { t } from "../lib/i18n";

interface PaginationProps {
  start: number;
  shown: number;
  total: number;
  page: number;
  pageSize: number;
  pageSizeOptions?: number[];
  hasPrevious: boolean;
  hasNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
  onPageSizeChange: (size: number) => void;
}

export default function Pagination(props: PaginationProps) {
  const end = () => (props.shown === 0 ? 0 : props.start + props.shown - 1);
  const pageSizeOptions = () => props.pageSizeOptions ?? [25, 50, 100, 200];

  return (
    <div class="pagination" aria-label={t("common.pagination")}>
      <span class="pagination-summary">
        {t("repos.pagination", {
          start: props.shown === 0 ? 0 : props.start,
          end: end(),
          total: props.total,
        })}
      </span>
      <label class="pagination-size">
        <span class="sr-only">{t("repos.pageSizeLabel")}</span>
        <select
          value={props.pageSize}
          onChange={(event) => props.onPageSizeChange(Number(event.currentTarget.value))}
        >
          {pageSizeOptions().map((size) => (
            <option value={size}>{t("repos.pageSize", { size })}</option>
          ))}
        </select>
      </label>
      <div class="pagination-controls">
        <button type="button" disabled={!props.hasPrevious} onClick={props.onPrevious}>
          {t("common.previous")}
        </button>
        <span class="pagination-page">{props.page}</span>
        <button type="button" disabled={!props.hasNext} onClick={props.onNext}>
          {t("common.next")}
        </button>
      </div>
    </div>
  );
}
