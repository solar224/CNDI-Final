import { useState, useEffect, useRef, useMemo } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, Area, ComposedChart, ReferenceLine } from 'recharts'
import { TrafficStats } from '../services/api'

interface TrafficChartProps {
    metrics: TrafficStats
}

interface DataPoint {
    time: string
    timestamp: number
    uplink: number
    downlink: number
    uplinkPkts: number
    downlinkPkts: number
}

type ChartMode = 'throughput' | 'packets' | 'combined'

export default function TrafficChart({ metrics }: TrafficChartProps) {
    const [history, setHistory] = useState<DataPoint[]>([])
    const lastUpdateRef = useRef<number>(0)
    const prevPacketsRef = useRef<{ uplink: number; downlink: number }>({ uplink: 0, downlink: 0 })
    // Auto-detect unit: if max throughput > 0.1 Mbps, use Mbps; otherwise use Kbps
    const [useKbps, setUseKbps] = useState(true)
    const [chartMode, setChartMode] = useState<ChartMode>('throughput')

    useEffect(() => {
        const now = Date.now()

        // Throttle updates to prevent too frequent re-renders (minimum 900ms between updates)
        if (now - lastUpdateRef.current < 900) {
            return
        }
        lastUpdateRef.current = now

        const timeStr = new Date().toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        })

        // Get raw Mbps values
        const rawUplink = metrics.uplink.throughput_mbps
        const rawDownlink = metrics.downlink.throughput_mbps

        // Calculate packets per second (delta)
        const uplinkPktsDelta = metrics.uplink.packets - prevPacketsRef.current.uplink
        const downlinkPktsDelta = metrics.downlink.packets - prevPacketsRef.current.downlink
        prevPacketsRef.current = { uplink: metrics.uplink.packets, downlink: metrics.downlink.packets }

        // Auto-detect if we should use Kbps or Mbps
        // If any value exceeds 0.1 Mbps (100 Kbps), switch to Mbps
        const maxRaw = Math.max(rawUplink, rawDownlink)
        if (maxRaw > 0.1) {
            setUseKbps(false)
        } else if (maxRaw < 0.01 && history.every(h => h.uplink < 100 && h.downlink < 100)) {
            setUseKbps(true)
        }

        setHistory(prev => {
            // Store values in the current unit for display
            // If useKbps, multiply by 1000 to convert Mbps to Kbps
            const multiplier = useKbps ? 1000 : 1

            // Keep more decimal precision for small values
            const uplinkValue = rawUplink * multiplier
            const downlinkValue = rawDownlink * multiplier

            const newPoint: DataPoint = {
                time: timeStr,
                timestamp: now,
                uplink: Math.round(uplinkValue * 10000) / 10000,
                downlink: Math.round(downlinkValue * 10000) / 10000,
                uplinkPkts: uplinkPktsDelta > 0 ? uplinkPktsDelta : 0,
                downlinkPkts: downlinkPktsDelta > 0 ? downlinkPktsDelta : 0,
            }

            // Debug log to help troubleshoot
            if (rawUplink > 0 || rawDownlink > 0) {
                console.log(`TrafficChart: raw=${rawUplink.toFixed(6)}/${rawDownlink.toFixed(6)} Mbps, display=${newPoint.uplink}/${newPoint.downlink} ${useKbps ? 'Kbps' : 'Mbps'}`)
            }

            const newHistory = [...prev, newPoint]

            // Keep only last 60 entries (1 minute of data at 1s interval)
            if (newHistory.length > 60) {
                return newHistory.slice(-60)
            }
            return newHistory
        })
    }, [metrics, useKbps])

    // Calculate statistics
    const stats = useMemo(() => {
        if (history.length === 0) return null

        const uplinkValues = history.map(h => h.uplink)
        const downlinkValues = history.map(h => h.downlink)
        const uplinkPktsValues = history.map(h => h.uplinkPkts)
        const downlinkPktsValues = history.map(h => h.downlinkPkts)

        return {
            uplink: {
                avg: uplinkValues.reduce((a, b) => a + b, 0) / uplinkValues.length,
                max: Math.max(...uplinkValues),
                min: Math.min(...uplinkValues.filter(v => v > 0) || [0]),
                current: uplinkValues[uplinkValues.length - 1] || 0,
            },
            downlink: {
                avg: downlinkValues.reduce((a, b) => a + b, 0) / downlinkValues.length,
                max: Math.max(...downlinkValues),
                min: Math.min(...downlinkValues.filter(v => v > 0) || [0]),
                current: downlinkValues[downlinkValues.length - 1] || 0,
            },
            packets: {
                uplinkTotal: uplinkPktsValues.reduce((a, b) => a + b, 0),
                downlinkTotal: downlinkPktsValues.reduce((a, b) => a + b, 0),
                uplinkAvg: uplinkPktsValues.reduce((a, b) => a + b, 0) / uplinkPktsValues.length,
                downlinkAvg: downlinkPktsValues.reduce((a, b) => a + b, 0) / downlinkPktsValues.length,
            }
        }
    }, [history])

    // Calculate stable Y-axis domain based on data
    const yAxisDomain = useMemo(() => {
        if (history.length === 0) return [0, 1]

        const allValues = chartMode === 'packets'
            ? history.flatMap(d => [d.uplinkPkts, d.downlinkPkts])
            : history.flatMap(d => [d.uplink, d.downlink])
        const maxValue = Math.max(...allValues, 0.001)

        // Round up to nice intervals to prevent axis jumping
        let ceiling: number
        if (chartMode === 'packets') {
            if (maxValue <= 10) ceiling = 10
            else if (maxValue <= 50) ceiling = 50
            else if (maxValue <= 100) ceiling = 100
            else if (maxValue <= 500) ceiling = 500
            else if (maxValue <= 1000) ceiling = 1000
            else ceiling = Math.ceil(maxValue / 500) * 500
        } else if (useKbps) {
            // Kbps scale
            if (maxValue <= 0.1) ceiling = 0.5
            else if (maxValue <= 0.5) ceiling = 1
            else if (maxValue <= 1) ceiling = 2
            else if (maxValue <= 2) ceiling = 5
            else if (maxValue <= 5) ceiling = 10
            else if (maxValue <= 10) ceiling = 20
            else if (maxValue <= 20) ceiling = 50
            else if (maxValue <= 50) ceiling = 100
            else if (maxValue <= 100) ceiling = 200
            else if (maxValue <= 200) ceiling = 500
            else if (maxValue <= 500) ceiling = 1000
            else ceiling = Math.ceil(maxValue / 500) * 500
        } else {
            // Mbps scale
            if (maxValue <= 0.1) ceiling = 0.1
            else if (maxValue <= 0.5) ceiling = 0.5
            else if (maxValue <= 1) ceiling = 1
            else if (maxValue <= 2) ceiling = 2
            else if (maxValue <= 5) ceiling = 5
            else if (maxValue <= 10) ceiling = 10
            else if (maxValue <= 20) ceiling = 20
            else if (maxValue <= 50) ceiling = 50
            else if (maxValue <= 100) ceiling = 100
            else ceiling = Math.ceil(maxValue / 50) * 50
        }

        return [0, ceiling]
    }, [history, useKbps, chartMode])

    // Format X-axis ticks to show only every 10 seconds
    const formatXAxis = (time: string, index: number) => {
        if (history.length <= 10) return time
        // Show tick every 10 data points
        if (index % 10 === 0 || index === history.length - 1) {
            return time.slice(0, 5) // Show HH:MM only
        }
        return ''
    }

    if (history.length < 2) {
        return (
            <div className="h-64 flex items-center justify-center text-slate-400">
                <div className="text-center">
                    <div className="animate-pulse mb-2">📊</div>
                    <p>Collecting data...</p>
                </div>
            </div>
        )
    }

    const unit = chartMode === 'packets' ? 'pps' : (useKbps ? 'Kbps' : 'Mbps')

    return (
        <div className="space-y-4">
            {/* Chart Mode Selector & Stats */}
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-2">
                    <span className="text-sm text-slate-400">View:</span>
                    <div className="flex bg-slate-700 rounded-lg p-1">
                        {(['throughput', 'packets', 'combined'] as ChartMode[]).map(mode => (
                            <button
                                key={mode}
                                onClick={() => setChartMode(mode)}
                                className={`px-3 py-1 text-sm rounded-md transition-colors ${chartMode === mode
                                    ? 'bg-blue-500 text-white'
                                    : 'text-slate-400 hover:text-white'
                                    }`}
                            >
                                {mode === 'throughput' ? '📈 Throughput' : mode === 'packets' ? '📦 Packets' : '📊 Combined'}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Quick Stats */}
                {stats && (
                    <div className="flex gap-4 text-sm">
                        <div className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                            <span className="text-slate-400">UL:</span>
                            <span className="text-green-400 font-mono">
                                {chartMode === 'packets'
                                    ? `${stats.packets.uplinkAvg.toFixed(0)} pps`
                                    : `${stats.uplink.current.toFixed(2)} ${unit}`}
                            </span>
                            <span className="text-slate-500 text-xs">(avg: {stats.uplink.avg.toFixed(2)})</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
                            <span className="text-slate-400">DL:</span>
                            <span className="text-blue-400 font-mono">
                                {chartMode === 'packets'
                                    ? `${stats.packets.downlinkAvg.toFixed(0)} pps`
                                    : `${stats.downlink.current.toFixed(2)} ${unit}`}
                            </span>
                            <span className="text-slate-500 text-xs">(avg: {stats.downlink.avg.toFixed(2)})</span>
                        </div>
                    </div>
                )}
            </div>

            {/* Chart */}
            <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                    {chartMode === 'combined' ? (
                        <ComposedChart data={history} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis
                                dataKey="time"
                                stroke="#64748b"
                                fontSize={11}
                                tickLine={false}
                                tickFormatter={formatXAxis}
                                interval={0}
                            />
                            <YAxis
                                yAxisId="left"
                                stroke="#64748b"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                domain={yAxisDomain}
                                label={{ value: unit, angle: -90, position: 'insideLeft', style: { fill: '#64748b', fontSize: 11 } }}
                            />
                            <YAxis
                                yAxisId="right"
                                orientation="right"
                                stroke="#64748b"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                label={{ value: 'pps', angle: 90, position: 'insideRight', style: { fill: '#64748b', fontSize: 11 } }}
                            />
                            <Tooltip
                                contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                                labelStyle={{ color: '#e2e8f0' }}
                            />
                            <Legend />
                            <Area yAxisId="left" type="monotone" dataKey="uplink" fill="#22c55e" fillOpacity={0.2} stroke="#22c55e" strokeWidth={2} name={`↑ UL (${unit})`} />
                            <Area yAxisId="left" type="monotone" dataKey="downlink" fill="#3b82f6" fillOpacity={0.2} stroke="#3b82f6" strokeWidth={2} name={`↓ DL (${unit})`} />
                            <Line yAxisId="right" type="monotone" dataKey="uplinkPkts" stroke="#86efac" strokeWidth={1} strokeDasharray="5 5" dot={false} name="↑ UL pps" />
                            <Line yAxisId="right" type="monotone" dataKey="downlinkPkts" stroke="#93c5fd" strokeWidth={1} strokeDasharray="5 5" dot={false} name="↓ DL pps" />
                        </ComposedChart>
                    ) : (
                        <LineChart data={history} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                            <XAxis
                                dataKey="time"
                                stroke="#64748b"
                                fontSize={11}
                                tickLine={false}
                                tickFormatter={formatXAxis}
                                interval={0}
                                tick={{ fill: '#64748b' }}
                            />
                            <YAxis
                                stroke="#64748b"
                                fontSize={12}
                                tickLine={false}
                                axisLine={false}
                                domain={yAxisDomain}
                                tickFormatter={(value) => `${value}`}
                                width={50}
                                label={{
                                    value: unit,
                                    angle: -90,
                                    position: 'insideLeft',
                                    style: { fill: '#64748b', fontSize: 11 }
                                }}
                            />
                            {stats && chartMode === 'throughput' && (
                                <>
                                    <ReferenceLine y={stats.uplink.avg} stroke="#22c55e" strokeDasharray="3 3" strokeOpacity={0.5} />
                                    <ReferenceLine y={stats.downlink.avg} stroke="#3b82f6" strokeDasharray="3 3" strokeOpacity={0.5} />
                                </>
                            )}
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: '#1e293b',
                                    border: '1px solid #334155',
                                    borderRadius: '8px',
                                }}
                                labelStyle={{ color: '#e2e8f0' }}
                                formatter={(value: number, name: string) => [
                                    chartMode === 'packets' ? `${value} pps` : `${value.toFixed(3)} ${unit}`,
                                    name
                                ]}
                            />
                            <Legend />
                            <Line
                                type="monotone"
                                dataKey={chartMode === 'packets' ? 'uplinkPkts' : 'uplink'}
                                stroke="#22c55e"
                                strokeWidth={2}
                                dot={false}
                                name="↑ Uplink"
                                isAnimationActive={false}
                            />
                            <Line
                                type="monotone"
                                dataKey={chartMode === 'packets' ? 'downlinkPkts' : 'downlink'}
                                stroke="#3b82f6"
                                strokeWidth={2}
                                dot={false}
                                name="↓ Downlink"
                                isAnimationActive={false}
                            />
                        </LineChart>
                    )}
                </ResponsiveContainer>
            </div>

            {/* Statistics Summary */}
            {stats && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                    <div className="bg-slate-700/30 rounded-lg p-2">
                        <div className="text-xs text-slate-500">Peak Uplink</div>
                        <div className="text-green-400 font-mono">{stats.uplink.max.toFixed(2)} {unit}</div>
                    </div>
                    <div className="bg-slate-700/30 rounded-lg p-2">
                        <div className="text-xs text-slate-500">Peak Downlink</div>
                        <div className="text-blue-400 font-mono">{stats.downlink.max.toFixed(2)} {unit}</div>
                    </div>
                    <div className="bg-slate-700/30 rounded-lg p-2">
                        <div className="text-xs text-slate-500">UL Packets (60s)</div>
                        <div className="text-green-400/80 font-mono">{stats.packets.uplinkTotal.toLocaleString()}</div>
                    </div>
                    <div className="bg-slate-700/30 rounded-lg p-2">
                        <div className="text-xs text-slate-500">DL Packets (60s)</div>
                        <div className="text-blue-400/80 font-mono">{stats.packets.downlinkTotal.toLocaleString()}</div>
                    </div>
                </div>
            )}
        </div>
    )
}
