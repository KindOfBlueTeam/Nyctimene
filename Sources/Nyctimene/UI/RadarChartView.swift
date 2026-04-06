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

                // Score text (above badge polygon)
                VStack(spacing: 1) {
                    Text("\(score)")
                        .font(.system(size: 22, weight: .black, design: .rounded))
                        .foregroundColor(accentColor)
                    Text("/ 100")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                .position(x: cx, y: cy)
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

// MARK: - XY scatter view (exactly 2 sources)

struct XYRiskView: View {
    let axes:      [RadarAxis]   // axes[0] = X axis, axes[1] = Y axis
    let score:     Int
    let riskLevel: RiskLevel

    private let padL: CGFloat = 50
    private let padB: CGFloat = 50
    private let padT: CGFloat = 14
    private let padR: CGFloat = 14
    private let badgeR: CGFloat = 22

    var body: some View {
        GeometryReader { geo in
            let w    = geo.size.width
            let h    = geo.size.height
            let pw   = w - padL - padR
            let ph   = h - padB - padT

            // Screen coords: origin = top-left, Y grows down
            // Plot origin (bottom-left in chart space) = (padL, h - padB)
            let xFrac = levelFraction(axes[0].level)
            let yFrac = levelFraction(axes[1].level)
            let dotX  = padL + xFrac * pw
            let dotY  = (h - padB) - yFrac * ph

            ZStack {
                Canvas { ctx, _ in
                    let plotTop    = padT
                    let plotBottom = h - padB
                    let plotLeft   = padL
                    let plotRight  = padL + pw

                    // Grid lines at each level (0/4, 1/4, 2/4, 3/4, 4/4)
                    for i in 0...4 {
                        let t = CGFloat(i) / 4.0
                        let isEdge = (i == 0 || i == 4)
                        let opacity: CGFloat = isEdge ? 0.28 : 0.10

                        var vLine = Path()
                        vLine.move(to: .init(x: plotLeft + t * pw, y: plotTop))
                        vLine.addLine(to: .init(x: plotLeft + t * pw, y: plotBottom))
                        ctx.stroke(vLine, with: .color(.secondary.opacity(opacity)),
                                   lineWidth: isEdge ? 1 : 0.5)

                        var hLine = Path()
                        hLine.move(to: .init(x: plotLeft, y: plotBottom - t * ph))
                        hLine.addLine(to: .init(x: plotRight, y: plotBottom - t * ph))
                        ctx.stroke(hLine, with: .color(.secondary.opacity(opacity)),
                                   lineWidth: isEdge ? 1 : 0.5)
                    }

                    // Crosshair dashes to the badge
                    var cv = Path()
                    cv.move(to: .init(x: dotX, y: plotTop))
                    cv.addLine(to: .init(x: dotX, y: plotBottom))
                    ctx.stroke(cv, with: .color(riskAccent(riskLevel).opacity(0.28)),
                               style: StrokeStyle(lineWidth: 1, dash: [3, 3]))

                    var ch = Path()
                    ch.move(to: .init(x: plotLeft, y: dotY))
                    ch.addLine(to: .init(x: plotRight, y: dotY))
                    ctx.stroke(ch, with: .color(riskAccent(riskLevel).opacity(0.28)),
                               style: StrokeStyle(lineWidth: 1, dash: [3, 3]))

                    // Badge hexagon at the intersection — this IS the data point
                    let badge = hexPath(cx: dotX, cy: dotY, r: badgeR)
                    ctx.fill(badge, with: .color(Color(NSColor.windowBackgroundColor)))
                    ctx.stroke(badge, with: .color(riskAccent(riskLevel).opacity(0.8)), lineWidth: 1.5)
                }

                // Score in badge
                VStack(spacing: 0) {
                    Text("\(score)")
                        .font(.system(size: 13, weight: .black, design: .rounded))
                        .foregroundColor(riskAccent(riskLevel))
                    Text("/ 100")
                        .font(.system(size: 6, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                .position(x: dotX, y: dotY)

                // X axis source label (bottom center)
                Text(axes[0].label)
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(axisLabelColor(axes[0].level))
                    .position(x: padL + pw / 2, y: h - padB / 2)

                // Y axis source label (left, rotated)
                Text(axes[1].label)
                    .font(.system(size: 9, weight: .bold))
                    .foregroundColor(axisLabelColor(axes[1].level))
                    .rotationEffect(.degrees(-90))
                    .position(x: padL / 2 - 4, y: padT + ph / 2)

                // X endpoint tick labels
                Text("N/A")
                    .font(.system(size: 6)).foregroundColor(.secondary.opacity(0.45))
                    .position(x: padL, y: h - padB + 10)
                Text("Confirmed")
                    .font(.system(size: 6)).foregroundColor(.secondary.opacity(0.45))
                    .position(x: padL + pw, y: h - padB + 10)

                // Y endpoint tick labels
                Text("N/A")
                    .font(.system(size: 6)).foregroundColor(.secondary.opacity(0.45))
                    .position(x: padL - 16, y: h - padB)
                Text("Cfm")
                    .font(.system(size: 6)).foregroundColor(.secondary.opacity(0.45))
                    .position(x: padL - 16, y: padT)
            }
        }
    }

    private func levelFraction(_ level: Int) -> CGFloat {
        guard level >= 2 else { return 0 }
        return CGFloat(level - 1) / 4.0
    }

    private func axisLabelColor(_ level: Int) -> Color {
        switch level {
        case 2: return .green
        case 3: return .yellow
        case 4: return .orange
        case 5: return .red
        default: return .secondary
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
