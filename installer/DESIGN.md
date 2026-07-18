---
name: Certael Setup
description: A calm native setup workspace for verified Certael suite installation and recovery.
colors:
  canvas: "#0B121B"
  sidebar: "#111C28"
  surface: "#182534"
  border: "#2A3A4C"
  ink: "#F4F7FA"
  secondary-ink: "#B7C3D0"
  muted-ink: "#8F9EAE"
  assurance: "#58C7D4"
  action: "#286873"
  warning: "#F0C36B"
  failure: "#FFB4A9"
typography:
  title:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "24px"
    fontWeight: 600
  heading:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "18px"
    fontWeight: 600
  body:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
  label:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 600
rounded:
  control: "4px"
  panel: "8px"
spacing:
  compact: "8px"
  standard: "12px"
  section: "24px"
  frame: "32px"
---

# Design System: Certael Setup

## Overview

The setup application uses a quiet two-column workspace: a narrow persistent phase rail and one primary task surface. Technical detail lives in a collapsible transcript at the bottom rather than competing with the decision in front of the operator.

## Components

- Native labeled text fields with adjacent Browse controls.
- One primary action per phase, plus explicit Back or Cancel actions.
- A semantic phase rail using numbers, labels, and completed/active text—not color alone.
- A component review list that names each selected package and version.
- A redacted monospace transcript with save/export support.
- Inline outcome panels for verified, complete, cancelled, rolled back, and failed states.

## Layout and behavior

- Default window: 1060×760; minimum: 820×620.
- Sidebar remains 230 logical pixels; content uses a readable 720-pixel maximum measure.
- The 820-pixel minimum preserves the phase rail and a usable content column; native OS scaling and text wrapping remain supported without hiding the active action.
- No fake percentages. Download and operation activity is indeterminate unless byte totals are reported by the installer engine.
- Controls retain native focus, keyboard, scaling, and accessibility behavior on every OS.
