export function EmptyState({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300/90 bg-gradient-to-br from-white to-slate-50/85 p-8 text-center">
      <h3 className="font-heading text-base font-semibold text-slate-900">{title}</h3>
      <p className="mx-auto mt-2 max-w-xl text-sm text-slate-600">{description}</p>
    </div>
  );
}

