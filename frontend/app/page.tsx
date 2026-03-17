"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { readToken } from "@/lib/auth-storage";

export default function HomePage(): null {
  const router = useRouter();

  useEffect(() => {
    const token = readToken();
    const joinToken = new URLSearchParams(window.location.search).get("join");
    if (!token && joinToken && joinToken.trim()) {
      router.replace(`/signup/invite?token=${encodeURIComponent(joinToken.trim())}`);
      return;
    }
    router.replace(token ? "/chat" : "/login");
  }, [router]);

  return null;
}
