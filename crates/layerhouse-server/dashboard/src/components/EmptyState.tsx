export default function EmptyState(props: { icon?: string; title: string; description?: string }) {
  return (
    <div class="empty">
      {props.icon && <div class="empty-icon">{props.icon}</div>}
      <h3>{props.title}</h3>
      {props.description && <p>{props.description}</p>}
    </div>
  );
}
