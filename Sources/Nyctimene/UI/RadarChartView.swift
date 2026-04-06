import SwiftUI
import NyctimeneCore

// MARK: - Axis model

struct RadarAxis {
    let label:     String   // short abbreviation shown on chart
    let level:     Int      // 1–5  (1 = N/A, 2 = clean … 5 = confirmed malicious)
    let rawDetail: String?  // e.g. "11 / 94 engines" — used in SingleSourceRiskView
}

// MARK: - Radar chart (3+ sources)

struct RadarChartView: View {
    let axes:      [RadarAxis]
    let score:     Int          // 1–100 composite
    let riskLevel: RiskLevel

    private let ringCount:  Int      = 4
    private let labelPad:   CGFloat  = 22
    private let dotRadius:  CGFloat  = 3.5

    var body: some View {
        GeometryReader { geo in
            let cx     = geo.size.width  / 2
            let cy     = geo.size.height / 2
            let radius = min(geo.size.width, geo.size.height) / 2 - labelPad

            ZStack {
                Canvas { ctx, _ in
                    guard !axes.isEmpty else { return }

                    // 1. Background rings
                    for ring in 1...ringCount {
                        let r    = radius * CGFloat(ring) / CGFloat(ringCount)
                        let path = polygonPath(cx: cx, cy: cy, radius: r, count: axes.count)
                        let isOuter = ring == ringCount
                        ctx.stroke(path,
                                   with: .color(.secondary.opacity(isOuter ? 0.35 : 0.18)),
                                   lineWidth: isOuter ? 1.0 : 0.5)
                    }

                    // 2. Axis spokes
                    for i in 0..<axes.count {
                        let angle = axisAngle(i)
                        var p = Path()
                        p.move(to: CGPoint(x: cx, y: cy))
                        p.addLine(to: CGPoint(x: cx + cos(angle) * radius,
                                              y: cy + sin(angle) * radius))
                        ctx.stroke(p, with: .color(.secondary.opacity(0.2)), lineWidth: 0.5)
                    }

                    // 3. Data polygon — fill
                    let dataPoly = dataPolygon(cx: cx, cy: cy, radius: radius)
                    ctx.fill(dataPoly, with: .color(accentColor.opacity(0.22)))

                    // 4. Data polygon — stroke
                    ctx.stroke(dataPoly,
                               with: .color(accentColor.opacity(0.85)),
                               lineWidth: 1.5)

                    // 5. Data dots
                    for i in 0..<axes.count {
                        let pt   = dataPoint(index: i, cx: cx, cy: cy, radius: radius)
                        let rect = CGRect(x: pt.x - dotRadius, y: pt.y - dotRadius,
                                          width: dotRadius * 2, height: dotRadius * 2)
                        ctx.fill(Path(ellipseIn: rect),
                                 with: .color(levelColor(axes[i].level)))
                    }

                    // 6. Center score badge — filled polygon framing the score text
                    let badgeRadius = radius * 0.30
                    let badgePoly   = polygonPath(cx: cx, cy: cy, radius: badgeRadius, count: axes.count)
                    ctx.fill(badgePoly, with: .color(Color(NSColor.windowBackgroundColor)))
                    ctx.stroke(badgePoly, with: .color(accentColor.opacity(0.7)), lineWidth: 1.5)
                }

                // Axis labels
                if !axes.isEmpty {
                    ForEach(0..<axes.count, id: \.self) { i in
                        let angle = axisAngle(i)
                        let r     = radius + labelPad * 0.9
                        Text(axes[i].label)
                            .font(.system(size: 8.5, weight: .bold))
                            .foregroundColor(labelColor(axes[i].level))
                            .position(x: cx + cos(angle) * r,
                                      y: cy + sin(angle) * r)
                    }
                }

                // (center badge polygon is drawn empty — branding element only)
            }
        }
    }

    // MARK: - Geometry helpers

    private func axisAngle(_ i: Int) -> CGFloat {
        CGFloat(-Double.pi / 2) + CGFloat(i) * CGFloat(2 * Double.pi / Double(axes.count))
    }

    private func levelFraction(_ level: Int) -> CGFloat {
        guard level >= 2 else { return 0 }
        return CGFloat(level - 1) / 4.0
    }

    private func dataPoint(index i: Int, cx: CGFloat, cy: CGFloat, radius: CGFloat) -> CGPoint {
        let angle = axisAngle(i)
        let r     = radius * levelFraction(axes[i].level)
        return CGPoint(x: cx + cos(angle) * r, y: cy + sin(angle) * r)
    }

    private func polygonPath(cx: CGFloat, cy: CGFloat, radius: CGFloat, count: Int) -> Path {
        var path = Path()
        for i in 0..<count {
            let a  = CGFloat(-Double.pi / 2) + CGFloat(i) * CGFloat(2 * Double.pi / Double(count))
            let pt = CGPoint(x: cx + cos(a) * radius, y: cy + sin(a) * radius)
            i == 0 ? path.move(to: pt) : path.addLine(to: pt)
        }
        path.closeSubpath()
        return path
    }

    private func dataPolygon(cx: CGFloat, cy: CGFloat, radius: CGFloat) -> Path {
        var path = Path()
        for i in 0..<axes.count {
            let pt = dataPoint(index: i, cx: cx, cy: cy, radius: radius)
            i == 0 ? path.move(to: pt) : path.addLine(to: pt)
        }
        path.closeSubpath()
        return path
    }

    // MARK: - Colors

    private var accentColor: Color { riskAccent(riskLevel) }

    private func levelColor(_ level: Int) -> Color {
        switch level {
        case 1:  return .secondary.opacity(0.4)
        case 2:  return .green
        case 3:  return .yellow
        case 4:  return .orange
        case 5:  return .red
        default: return .secondary
        }
    }

    private func labelColor(_ level: Int) -> Color {
        level <= 1 ? .secondary : levelColor(level)
    }
}

// MARK: - Balance beam view (exactly 2 sources)

struct XYRiskView: View {
    let axes:      [RadarAxis]   // axes[0] = left source, axes[1] = right source
    let score:     Int
    let riskLevel: RiskLevel

    private let beamH:   CGFloat = 14     // beam bar thickness
    private let badgeR:  CGFloat = 24     // hexagon half-width
    private let tickH:   CGFloat = 20     // tick mark height (above + below beam)

    var body: some View {
        GeometryReader { geo in
            let w    = geo.size.width
            let h    = geo.size.height
            let padX: CGFloat = 28                      // horizontal inset for beam
            let beamW = w - padX * 2
            let cy    = h / 2                           // vertical center

            // Level fractions (1→0, 2→0.25, 3→0.5, 4→0.75, 5→1.0)
            let lFrac = levelFraction(axes[0].level)
            let rFrac = levelFraction(axes[1].level)

            // Badge position: 0.5 = centered (both equal). If right is higher,
            // badge slides right; if left is higher, it slides left.
            let balance = 0.5 + (rFrac - lFrac) / 2.0
            let badgeX  = padX + balance * beamW

            let lColor = levelColor(axes[0].level)
            let rColor = levelColor(axes[1].level)
            let accent = riskAccent(riskLevel)

            ZStack {
                Canvas { ctx, _ in
                    let beamTop = cy - beamH / 2
                    let beamBot = cy + beamH / 2
                    let beamLeft  = padX
                    let beamRight = padX + beamW
                    let midX      = padX + beamW / 2

                    // 1. Beam track (full width, dark)
                    let track = Path(roundedRect:
                        CGRect(x: beamLeft, y: beamTop, width: beamW, height: beamH),
                        cornerRadius: beamH / 2)
                    ctx.fill(track, with: .color(.secondary.opacity(0.12)))
                    ctx.stroke(track, with: .color(.secondary.opacity(0.25)), lineWidth: 0.5)

                    // 2. Left source fill — from left edge to center, height = level fraction
                    let lFillW = (midX - beamLeft) * lFrac
                    if lFillW > 0 {
                        let lRect = CGRect(x: midX - lFillW, y: beamTop, width: lFillW, height: beamH)
                        let lClip = Path(roundedRect:
                            CGRect(x: beamLeft, y: beamTop, width: beamW, height: beamH),
                            cornerRadius: beamH / 2)
                        ctx.clip(to: lClip)
                        ctx.fill(Path(lRect), with: .color(lColor.opacity(0.45)))
                        // Reset clip by drawing full size
                        ctx.clip(to: Path(CGRect(x: 0, y: 0, width: w, height: h)))
                    }

                    // 3. Right source fill — from center to right edge
                    let rFillW = (beamRight - midX) * rFrac
                    if rFillW > 0 {
                        let rRect = CGRect(x: midX, y: beamTop, width: rFillW, height: beamH)
                        let rClip = Path(roundedRect:
                            CGRect(x: beamLeft, y: beamTop, width: beamW, height: beamH),
                            cornerRadius: beamH / 2)
                        ctx.clip(to: rClip)
                        ctx.fill(Path(rRect), with: .color(rColor.opacity(0.45)))
                        ctx.clip(to: Path(CGRect(x: 0, y: 0, width: w, height: h)))
                    }

                    // 4. Tick marks at each level (5 ticks per side)
                    for side in 0...1 {
                        let sideLeft  = side == 0 ? beamLeft : midX
                        let sideW     = side == 0 ? (midX - beamLeft) : (beamRight - midX)
                        for i in 0...4 {
                            let t  = CGFloat(i) / 4.0
                            let tx: CGFloat
                            if side == 0 {
                                tx = midX - t * sideW     // left side: ticks go outward from center
                            } else {
                                tx = midX + t * sideW     // right side: ticks go outward from center
                            }
                            let isEnd = (i == 4)
                            var tick = Path()
                            tick.move(to: .init(x: tx, y: cy - tickH / 2))
                            tick.addLine(to: .init(x: tx, y: cy + tickH / 2))
                            ctx.stroke(tick,
                                       with: .color(.secondary.opacity(isEnd ? 0.3 : 0.15)),
                                       lineWidth: isEnd ? 1 : 0.5)
                        }
                    }

                    // 5. Center line
                    var centerLine = Path()
                    centerLine.move(to: .init(x: midX, y: cy - tickH / 2 - 2))
                    centerLine.addLine(to: .init(x: midX, y: cy + tickH / 2 + 2))
                    ctx.stroke(centerLine, with: .color(.secondary.opacity(0.4)), lineWidth: 1)

                    // 6. Connector line from center to badge
                    var connector = Path()
                    connector.move(to: .init(x: midX, y: cy))
                    connector.addLine(to: .init(x: badgeX, y: cy))
                    ctx.stroke(connector, with: .color(accent.opacity(0.5)),
                               style: StrokeStyle(lineWidth: 1.5, dash: [4, 3]))

                    // 7. Badge hexagon at the balance point
                    let badge = hexPath(cx: badgeX, cy: cy, r: badgeR)
                    ctx.fill(badge, with: .color(Color(NSColor.windowBackgroundColor)))
                    ctx.stroke(badge, with: .color(accent.opacity(0.8)), lineWidth: 1.5)
                }

                // Source label + level indicator — LEFT
                VStack(spacing: 4) {
                    Text(axes[0].label)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(lColor)
                    Text(levelLabel(axes[0].level))
                        .font(.system(size: 8, weight: .medium))
                        .foregroundColor(.secondary)
                    if let detail = axes[0].rawDetail {
                        Text(detail)
                            .font(.system(size: 7.5).monospaced())
                            .foregroundColor(.secondary.opacity(0.7))
                    }
                }
                .position(x: padX + beamW * 0.15, y: cy - 58)

                // Source label + level indicator — RIGHT
                VStack(spacing: 4) {
                    Text(axes[1].label)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(rColor)
                    Text(levelLabel(axes[1].level))
                        .font(.system(size: 8, weight: .medium))
                        .foregroundColor(.secondary)
                    if let detail = axes[1].rawDetail {
                        Text(detail)
                            .font(.system(size: 7.5).monospaced())
                            .foregroundColor(.secondary.opacity(0.7))
                    }
                }
                .position(x: padX + beamW * 0.85, y: cy - 58)

                // "Clean" / "Confirmed" endpoint labels
                Text("Clean")
                    .font(.system(size: 7)).foregroundColor(.secondary.opacity(0.45))
                    .position(x: padX, y: cy + tickH / 2 + 12)
                Text("▼")
                    .font(.system(size: 7)).foregroundColor(.secondary.opacity(0.2))
                    .position(x: padX + beamW / 2, y: cy + tickH / 2 + 12)
                Text("Clean")
                    .font(.system(size: 7)).foregroundColor(.secondary.opacity(0.45))
                    .position(x: padX + beamW, y: cy + tickH / 2 + 12)

                // Agreement label below center
                Text(agreementLabel)
                    .font(.system(size: 9, weight: .medium))
                    .foregroundColor(accent.opacity(0.8))
                    .position(x: w / 2, y: cy + 48)
            }
        }
    }

    /// Human-readable agreement summary
    private var agreementLabel: String {
        let l = axes[0].level, r = axes[1].level
        if l == r { return "Sources agree" }
        let diff = abs(l - r)
        return diff >= 3 ? "Sources disagree" : "Partial agreement"
    }

    private func levelFraction(_ level: Int) -> CGFloat {
        guard level >= 2 else { return 0 }
        return CGFloat(level - 1) / 4.0
    }

    private func levelColor(_ level: Int) -> Color {
        switch level {
        case 2:  return .green
        case 3:  return .yellow
        case 4:  return .orange
        case 5:  return .red
        default: return .secondary.opacity(0.4)
        }
    }

    private func levelLabel(_ level: Int) -> String {
        switch level {
        case 2:  return "Clean"
        case 3:  return "Low signal"
        case 4:  return "Likely"
        case 5:  return "Confirmed"
        default: return "N/A"
        }
    }

    private func hexPath(cx: CGFloat, cy: CGFloat, r: CGFloat) -> Path {
        var path = Path()
        for i in 0..<6 {
            let a = CGFloat(-Double.pi / 2) + CGFloat(i) * (2 * .pi / 6)
            let pt = CGPoint(x: cx + cos(a) * r, y: cy + sin(a) * r)
            i == 0 ? path.move(to: pt) : path.addLine(to: pt)
        }
        path.closeSubpath()
        return path
    }
}

// MARK: - Single source view (exactly 1 source)

struct SingleSourceRiskView: View {
    let axis: RadarAxis

    private let levelNames:  [String] = ["", "N/A", "Clean", "Low Signal", "Likely Malicious", "Confirmed"]
    private let levelColors: [Color]  = [.clear, .secondary, .green, .yellow, .orange, .red]

    var body: some View {
        let safe  = max(1, min(5, axis.level))
        let color = levelColors[safe]
        let frac  = CGFloat(safe - 1) / 4.0

        VStack(spacing: 14) {
            Text(axis.label)
                .font(.system(size: 15, weight: .bold))
                .foregroundColor(color)

            ZStack {
                Circle()
                    .stroke(Color.secondary.opacity(0.12), lineWidth: 10)
                Circle()
                    .trim(from: 0, to: frac)
                    .stroke(color, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                VStack(spacing: 2) {
                    Text("\(safe - 1)")
                        .font(.system(size: 34, weight: .black, design: .rounded))
                        .foregroundColor(color)
                    Text("/ 4")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .frame(width: 110, height: 110)

            Text(levelNames[safe])
                .font(.headline.bold())
                .foregroundColor(color)

            if let detail = axis.rawDetail {
                Text(detail)
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Shared color helper

private func riskAccent(_ level: RiskLevel) -> Color {
    switch level {
    case .malicious:  return .red
    case .suspicious: return .orange
    case .clean:      return .green
    default:          return .secondary
    }
}
