import { Suspense } from "react";

import InviteClient from "./invite-client";

export default function InviteSignupPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-slate-950 px-4 py-8 sm:px-6 lg:px-8">
          <div className="mx-auto h-[84vh] w-full max-w-6xl rounded-3xl border border-slate-800 bg-slate-900/85" />
        </div>
      }
    >
      <InviteClient />
    </Suspense>
  );
}
