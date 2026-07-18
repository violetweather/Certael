---
name: Certael Operator Console
description: A precise, calm, forensic workspace for explainable game-security decisions.
colors:
  night-bench: "#0B1114"
  deep-slate: "#10191D"
  raised-slate: "#162126"
  inspection-slate: "#1D2B31"
  structural-line: "#2D3D43"
  control-edge: "#5A6E73"
  evidence-white: "#E7F0F2"
  quiet-silver: "#A5B4B8"
  muted-label: "#7E8D91"
  verified-cyan: "#58C7C8"
  cyan-ink: "#071213"
  confirmed-green: "#75C99B"
  review-amber: "#D7AF62"
  restriction-rose: "#E48B8F"
  context-blue: "#79AEE8"
typography:
  heading:
    fontFamily: "IBM Plex Sans, Segoe UI, sans-serif"
    fontSize: "2rem"
    fontWeight: 300
    lineHeight: 1.25
  title:
    fontFamily: "IBM Plex Sans, Segoe UI, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.333
  subtitle:
    fontFamily: "IBM Plex Sans, Segoe UI, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 500
    lineHeight: 1.3
  body:
    fontFamily: "IBM Plex Sans, Segoe UI, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "IBM Plex Sans, Segoe UI, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 500
    lineHeight: 1.429
  metadata:
    fontFamily: "IBM Plex Sans, Segoe UI, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 500
    lineHeight: 1.5
  machine:
    fontFamily: "IBM Plex Mono, Consolas, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.429
rounded:
  micro: "3px"
  control: "4px"
  overlay: "6px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "24px"
  xxl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.verified-cyan}"
    textColor: "{colors.cyan-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  button-secondary:
    backgroundColor: "{colors.deep-slate}"
    textColor: "{colors.evidence-white}"
    typography: "{typography.label}"
    rounded: "{rounded.control}"
    padding: "10px 16px"
  field:
    backgroundColor: "{colors.night-bench}"
    textColor: "{colors.evidence-white}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "10px 12px"
---

# Design System: Certael Operator Console

## Overview

**Creative North Star: "The Forensic Workbench"**

The console feels like a carefully maintained forensic workbench used during a quiet, focused investigation: dark ambient surroundings, excellent task lighting, exact labels, and every important object placed where an experienced operator expects it. Linear supplies disciplined hierarchy, GitHub code review supplies traceable discussion around exact evidence, and forensic laboratory reports supply the standard for provenance and restrained authority.

The interface is dense because the work is dense, but never crowded or theatrical. A persistent rail, master-detail queues, dossier surfaces, evidence tables, and activity timelines form one predictable product grammar. Motion is restrained to state changes, focus movement, disclosure, and progress feedback.

**Key Characteristics:**

- Dark-only, teal-tinted graphite foundation
- Muted cyan accent on no more than 10% of a screen
- Stable divided surfaces instead of floating cards
- Technical humanist typography with meaningful monospace
- Visible provenance, state, permissions, and consequences

## Colors

Night Bench anchors the application. Deep, Raised, and Inspection Slate create depth by increasing lightness rather than adding shadow. Evidence White and Quiet Silver carry readable content. Verified Cyan is reserved for current selection, focus, interaction, and verified linkage.

Semantic colors reinforce labeled states: Confirmed Green for completed verification, Review Amber for caution or pending review, Restriction Rose for errors and restrictive consequences, and Context Blue for neutral information. None may communicate meaning alone.

**The Restrained Signal Rule.** The accent occupies no more than 10% of a screen and never decorates passive content.

**The Evidence-First Severity Rule.** Text, icon, and structure communicate severity; color only reinforces them.

## Typography

IBM Plex Sans carries all interface hierarchy and prose. IBM Plex Mono appears only for event IDs, hashes, policy and rule versions, timestamps in aligned data, and machine values. Body prose is never smaller than 1rem. Compact labels and table metadata may use 0.875rem while retaining adequate line height and contrast.

Headings use light or semibold weights rather than oversized scale. Numeric columns use tabular figures. Uppercase labels are rare, brief, and tracked at 0.06em.

**The Meaningful Mono Rule.** Never use monospace merely to make the product look technical.

## Elevation

The system is flat by default. Depth comes from tonal surfaces, persistent dividers, sticky regions, and temporary overlays. Resting work surfaces have no shadow. Menus and dialogs may use one diffuse shadow only when they physically overlap another task layer.

**The Stable Surface Rule.** Investigation content never becomes a floating collection of interchangeable cards.

## Components

Buttons are compact but maintain a 44px interaction target. Primary cyan buttons are rare and name the exact outcome. Secondary actions use Deep Slate with a Control Edge boundary. Restrictive actions remain neutral until the confirmation stage, where Restriction Rose reinforces explicit consequence copy.

Inputs always have visible labels. Control Edge supplies the 3:1 boundary; Verified Cyan supplies a 2px, offset `:focus-visible` ring. Errors appear below the field and are programmatically associated.

Tables use semantic headers, sticky regions where useful, visible row focus, and deterministic column alignment. Timelines use thin evidence-chain lines and square nodes. Cards are prohibited unless content is genuinely independent and actionable.

Navigation keeps the current location visible through icon, label when space permits, and a full-perimeter or surface treatment. Narrow layouts preserve context through drill-in headers and explicit return paths.

## Do's and Don'ts

### Do:

- **Do** keep evidence, provenance, rule version, timestamps, and activity visibly connected.
- **Do** use dense tables, timelines, and split panes when they reduce navigation.
- **Do** reserve Verified Cyan for interaction, selection, focus, and verified relationships.
- **Do** keep prose at 1rem and interaction targets at least 44px.
- **Do** name exact consequences before a bounded action can proceed.

### Don't:

- **Don't** build a neon “SOC wall” or alarm-heavy red dashboard.
- **Don't** use marketing-page layouts, oversized promotional typography, or fake metrics.
- **Don't** use glassmorphism, gradients, glowing borders, or decorative cyber imagery.
- **Don't** arrange the product as a generic card grid or nest cards inside cards.
- **Don't** show unexplained risk graphics, gauges, mystery graphs, or force-directed decoration.
- **Don't** communicate severity, integrity, or state by color alone.
- **Don't** use pulsing, flashing, or ambient animation to manufacture urgency.
