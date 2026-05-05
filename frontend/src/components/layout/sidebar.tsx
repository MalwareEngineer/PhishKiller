import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Package,
  GitBranch,
  Search,
  Users,
  Target,
  Layers,
  ChevronLeft,
  ChevronRight,
  FileDiff,
  Sparkles,
  Fingerprint,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { DarlaLogo } from "@/components/shared/darla-logo";
import { useState } from "react";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/kits", icon: Package, label: "Kits" },
  { to: "/investigations", icon: GitBranch, label: "Investigations" },
  { to: "/indicators", icon: Search, label: "Indicators" },
  { to: "/actors", icon: Users, label: "Actors" },
  { to: "/campaigns", icon: Target, label: "Campaigns" },
  { to: "/families", icon: Layers, label: "Families" },
  { to: "/phish-diff", icon: FileDiff, label: "PhishDiff" },
  { to: "/phish-match", icon: Sparkles, label: "PhishMatch" },
  { to: "/phishprint", icon: Fingerprint, label: "PhishPrint" },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "flex flex-col border-r border-border bg-sidebar text-sidebar-foreground transition-all duration-200",
        collapsed ? "w-16" : "w-56"
      )}
    >
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <DarlaLogo className="h-6 w-6 text-emerald-500" />
        {!collapsed && (
          <span className="text-lg font-bold tracking-tight">Darla</span>
        )}
      </div>

      <nav className="flex-1 space-y-1 p-2">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            title={collapsed ? label : undefined}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground"
              )
            }
          >
            <Icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-border p-2">
        <Button
          variant="ghost"
          size="sm"
          className="w-full justify-center"
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>
    </aside>
  );
}
