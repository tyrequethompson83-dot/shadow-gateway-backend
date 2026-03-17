import type { LucideIcon } from "lucide-react";
import { Activity, BarChart3, Settings } from "lucide-react";

export type NavItem = {
  href: string;
  label: string;
  shortLabel: string;
  icon: LucideIcon;
};

export const TEAM_CHAT_ROUTE = "/chat";

export const NAV_ITEMS: NavItem[] = [
  {
    href: "/activity",
    label: "Activity Feed",
    shortLabel: "Activity",
    icon: Activity,
  },
  {
    href: "/analytics",
    label: "Analytics",
    shortLabel: "Analytics",
    icon: BarChart3,
  },
  {
    href: "/settings",
    label: "Settings",
    shortLabel: "Settings",
    icon: Settings,
  },
];

export const PAGE_TITLES: Record<string, string> = {
  "/chat": "Team Chat",
  "/activity": "Activity Feed",
  "/analytics": "Analytics",
  "/settings": "Settings",
};
