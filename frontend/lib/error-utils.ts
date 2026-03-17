import { ApiError } from "@/lib/api";

export function detailMessage(detail: unknown, fallback: string): string {
  if (typeof detail === "string" && detail.trim()) {
    return detail;
  }
  if (detail && typeof detail === "object") {
    if ("message" in detail && typeof (detail as { message?: unknown }).message === "string") {
      return String((detail as { message: string }).message);
    }
    if ("detail" in detail) {
      return detailMessage((detail as { detail?: unknown }).detail, fallback);
    }
    if ("error" in detail) {
      return detailMessage((detail as { error?: unknown }).error, fallback);
    }
    if ("raw_error_json" in detail) {
      return detailMessage((detail as { raw_error_json?: unknown }).raw_error_json, fallback);
    }
  }
  return fallback;
}

export function errorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    return detailMessage(err.detail, fallback);
  }
  if (err instanceof Error && err.message.trim()) {
    return err.message;
  }
  return fallback;
}
