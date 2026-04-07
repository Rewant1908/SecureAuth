# Design System Document: The Sentinel Aesthetic

## 1. Overview & Creative North Star
**Creative North Star: "The Digital Curator"**
This design system moves away from the "noisy" dashboard clutter typical of cybersecurity and toward a high-end, editorial experience. We are not just displaying data; we are curating intelligence. The interface should feel like a premium, dark-mode command center—silent, powerful, and impeccably organized.

To break the "template" look, we utilize **Intentional Asymmetry**. Larger display type is paired with generous whitespace to create a rhythm that feels more like a high-end magazine than a generic SaaS tool. We avoid rigid grids in favor of **Layered Depth**, where the UI feels like a series of sophisticated glass planes hovering in a deep, digital void.

---

## 2. Colors & Tonal Depth
Our palette is rooted in a deep charcoal foundation, using precise teal and secondary accents to highlight critical AI insights.

### The "No-Line" Rule
**Explicit Instruction:** Do not use 1px solid borders to section content. Boundaries must be defined solely through background color shifts or subtle tonal transitions. Use `surface-container-low` against `surface` to create natural separation.

### Surface Hierarchy & Nesting
Treat the UI as a physical stack. We use the Material surface tiers to define importance without adding visual noise:
- **Base Layer:** `surface` (#0b1326) — The infinite void.
- **Sectioning:** `surface-container-low` (#131b2e) — For large sidebars or background groupings.
- **Primary Cards:** `surface-container` (#171f33) — The standard container for content.
- **Elevated Modals/Floating Elements:** `surface-container-highest` (#2d3449) — For elements that require immediate focus.

### The "Glass & Gradient" Rule
To provide "visual soul," use **Glassmorphism** for floating menus or navigation bars. Use `surface_variant` with a 60% opacity and a 20px backdrop-blur. 
- **Signature Texture:** Apply a linear gradient (Top-Left to Bottom-Right) from `primary` (#4cd6ff) to `primary_container` (#009dc1) on main action buttons to give them a "lit from within" glow.

---

## 3. Typography
We use a dual-typeface strategy to balance technical precision with authoritative elegance.

- **Display & Headlines (Manrope):** Chosen for its geometric modernism. Use `display-lg` and `headline-md` to create "Editorial Moments" in the dashboard—large, bold numbers or status updates that command the room.
- **UI & Body (Inter):** Chosen for its extreme legibility at small sizes. All functional data, labels, and paragraph text use Inter.

**Hierarchy as Identity:** 
Use `label-sm` in all-caps with increased letter-spacing (0.05rem) for technical metadata. This creates a "secure" and "coded" aesthetic common in high-end security interfaces.

---

## 4. Elevation & Depth
Depth is achieved through **Tonal Layering**, not structural lines.

- **The Layering Principle:** Place a `surface-container-lowest` card on a `surface-container-low` background. This creates a "sunken" or "lifted" effect through color value alone.
- **Ambient Shadows:** For floating elements, use a `12px 24px 48px` blur with 6% opacity. Use the `on-surface` color (#dae2fd) as the shadow tint rather than pure black to simulate a natural glow.
- **The "Ghost Border" Fallback:** If accessibility requires a border, use `outline-variant` (#414754) at **15% opacity**. It should be felt, not seen.

---

## 5. Components

### Buttons
- **Primary:** `primary` fill with `on-primary` text. Use a subtle `primary_container` outer glow on hover.
- **Secondary:** Ghost style. No fill, `outline` border (at 20% opacity), `primary` text.
- **Tertiary:** No border or fill. `primary` text. Use for low-emphasis actions like "Cancel."

### Cards & Lists
- **The Divider Ban:** Strictly forbid 1px horizontal lines between list items. Use **Vertical White Space** (24px - 32px) or a alternating subtle background shift (`surface-container-low` vs `surface-container`).
- **Roundedness:** Apply `xl` (1.5rem / 24px) to outer dashboard containers and `lg` (1rem / 16px) to internal cards.

### Input Fields
- **State-Driven Tints:** Instead of a heavy border on focus, use a subtle background transition to `surface_bright` and a `primary` "Ghost Border" at 30% opacity.
- **Validation:** Use `error` (#ffb4ab) for critical AI-detected threats, but keep the icons small and sharp to maintain the "Minimal" aesthetic.

### Additional Identity Components
- **Risk Indicator Rings:** Use thin, high-contrast strokes of `secondary` (Low Risk), `tertiary` (Medium), and `error` (High) with a `backdrop-blur` center to visualize AI confidence scores.

---

## 6. Do’s and Don’ts

### Do:
- **Embrace the Void:** Use "over-sized" margins (48px+) to let data breathe.
- **Layer Color:** Use `surface-tint` at 5% opacity as an overlay on images or charts to keep them unified within the dark theme.
- **Use Micro-interactions:** Buttons should have a soft "scale down" (0.98) on click to mimic physical glass.

### Don’t:
- **Don't use pure black (#000):** It destroys the "Deep Charcoal" premium feel. Always use the `surface` token.
- **Don't use high-contrast dividers:** They clutter the UI and break the "Digital Curator" aesthetic.
- **Don't crowd the sidebar:** Keep navigation links sparse. If a category has more than 5 items, use a nested glassmorphic flyout instead of a long list.
- **Don't use "Default" shadows:** Avoid the standard CSS `0 2px 4px rgba(0,0,0,0.5)`. It feels cheap. Use the Ambient Shadow rules in Section 4. 