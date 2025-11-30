import { TrafficStats, DropStats, SessionInfo } from '../services/api'
import TrafficChart from './TrafficChart'
import DropAlertPanel from './DropAlertPanel'
import SessionTable from './SessionTable'
import SessionTrafficChart from './SessionTrafficChart'
import Topology from './Topology'

interface DashboardProps {
    metrics: TrafficStats
    drops: DropStats
    sessions: SessionInfo[]
}

function formatBytes(bytes: number): string {
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`
    if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(2)} KB`
    return `${bytes} B`
}

function formatNumber(n: number): string {
    if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
    if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
    return n.toString()
}

function formatThroughput(mbps: number): { value: string; unit: string } {
    if (mbps >= 1000) return { value: (mbps / 1000).toFixed(2), unit: 'Gbps' }
    if (mbps >= 1) return { value: mbps.toFixed(2), unit: 'Mbps' }
    return { value: (mbps * 1000).toFixed(0), unit: 'Kbps' }
}

export default function Dashboard({ metrics, drops, sessions }: DashboardProps) {
    const uplinkTp = formatThroughput(metrics.uplink.throughput_mbps)
    const downlinkTp = formatThroughput(metrics.downlink.throughput_mbps)

    // Calculate totals
    const totalPackets = metrics.uplink.packets + metrics.downlink.packets
    const totalBytes = metrics.uplink.bytes + metrics.downlink.bytes
    const totalTEIDs = sessions.reduce((acc, s) => acc + s.teids.length, 0)

    return (
        <div className="space-y-6 pb-16">
            {/* Stats Cards - Enhanced */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Uplink Card */}
                <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700 hover:border-green-500/50 transition-colors">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-slate-400 text-sm">Uplink Traffic</span>
                        <span className="text-green-400 text-xs font-medium px-2 py-0.5 bg-green-500/20 rounded-full">↑ UL</span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className="text-3xl font-bold text-white">{uplinkTp.value}</span>
                        <span className="text-lg text-slate-400">{uplinkTp.unit}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className="text-slate-500 text-xs">Packets</div>
                            <div className="text-green-400 font-mono">{formatNumber(metrics.uplink.packets)}</div>
                        </div>
                        <div>
                            <div className="text-slate-500 text-xs">Bytes</div>
                            <div className="text-slate-300 font-mono">{formatBytes(metrics.uplink.bytes)}</div>
                        </div>
                    </div>
                    {/* Progress bar showing UL/DL ratio */}
                    <div className="mt-3">
                        <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-green-500 to-green-400 transition-all duration-500"
                                style={{ width: `${totalBytes > 0 ? (metrics.uplink.bytes / totalBytes) * 100 : 50}%` }}
                            />
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                            {totalBytes > 0 ? ((metrics.uplink.bytes / totalBytes) * 100).toFixed(1) : 50}% of total
                        </div>
                    </div>
                </div>

                {/* Downlink Card */}
                <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700 hover:border-blue-500/50 transition-colors">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-slate-400 text-sm">Downlink Traffic</span>
                        <span className="text-blue-400 text-xs font-medium px-2 py-0.5 bg-blue-500/20 rounded-full">↓ DL</span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className="text-3xl font-bold text-white">{downlinkTp.value}</span>
                        <span className="text-lg text-slate-400">{downlinkTp.unit}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className="text-slate-500 text-xs">Packets</div>
                            <div className="text-blue-400 font-mono">{formatNumber(metrics.downlink.packets)}</div>
                        </div>
                        <div>
                            <div className="text-slate-500 text-xs">Bytes</div>
                            <div className="text-slate-300 font-mono">{formatBytes(metrics.downlink.bytes)}</div>
                        </div>
                    </div>
                    {/* Progress bar showing DL/UL ratio */}
                    <div className="mt-3">
                        <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-blue-500 to-blue-400 transition-all duration-500"
                                style={{ width: `${totalBytes > 0 ? (metrics.downlink.bytes / totalBytes) * 100 : 50}%` }}
                            />
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                            {totalBytes > 0 ? ((metrics.downlink.bytes / totalBytes) * 100).toFixed(1) : 50}% of total
                        </div>
                    </div>
                </div>

                {/* Drop Rate Card */}
                <div className={`bg-slate-800/50 rounded-xl p-5 border transition-colors ${drops.rate_percent > 1
                    ? 'border-red-500 pulse-alert'
                    : drops.rate_percent > 0
                        ? 'border-yellow-500/50'
                        : 'border-slate-700 hover:border-green-500/50'
                    }`}>
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-slate-400 text-sm">Drop Rate</span>
                        <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${drops.rate_percent > 1
                            ? 'text-red-400 bg-red-500/20'
                            : drops.rate_percent > 0
                                ? 'text-yellow-400 bg-yellow-500/20'
                                : 'text-green-400 bg-green-500/20'
                            }`}>
                            {drops.rate_percent > 1 ? '⚠️ Critical' : drops.rate_percent > 0 ? '⚠️ Warning' : '✓ OK'}
                        </span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className={`text-3xl font-bold ${drops.rate_percent > 0 ? 'text-red-400' : 'text-white'
                            }`}>
                            {drops.rate_percent.toFixed(3)}
                        </span>
                        <span className="text-lg text-slate-400">%</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className="text-slate-500 text-xs">Total Drops</div>
                            <div className="text-red-400 font-mono">{formatNumber(drops.total)}</div>
                        </div>
                        <div>
                            <div className="text-slate-500 text-xs">Reasons</div>
                            <div className="text-slate-300 font-mono">{Object.keys(drops.by_reason || {}).length}</div>
                        </div>
                    </div>
                    {/* Drop reasons mini chart */}
                    {Object.keys(drops.by_reason || {}).length > 0 && (
                        <div className="mt-3 flex gap-1">
                            {Object.entries(drops.by_reason).slice(0, 3).map(([reason, count], idx) => (
                                <div
                                    key={reason}
                                    className="flex-1 h-1.5 rounded-full"
                                    style={{
                                        backgroundColor: ['#ef4444', '#f97316', '#eab308'][idx],
                                        opacity: 0.5 + (count / drops.total) * 0.5
                                    }}
                                    title={`${reason}: ${count}`}
                                />
                            ))}
                        </div>
                    )}
                </div>

                {/* Sessions Card */}
                <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700 hover:border-cyan-500/50 transition-colors">
                    <div className="flex items-center justify-between mb-3">
                        <span className="text-slate-400 text-sm">Active Sessions</span>
                        <span className="text-cyan-400 text-xs font-medium px-2 py-0.5 bg-cyan-500/20 rounded-full">PDU</span>
                    </div>
                    <div className="flex items-baseline gap-1">
                        <span className="text-3xl font-bold text-white">{sessions.length}</span>
                        <span className="text-lg text-slate-400">sessions</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-sm">
                        <div>
                            <div className="text-slate-500 text-xs">TEIDs</div>
                            <div className="text-purple-400 font-mono">{totalTEIDs}</div>
                        </div>
                        <div>
                            <div className="text-slate-500 text-xs">UE IPs</div>
                            <div className="text-slate-300 font-mono">{new Set(sessions.map(s => s.ue_ip)).size}</div>
                        </div>
                    </div>
                    {/* Session indicators */}
                    <div className="mt-3 flex gap-1">
                        {sessions.slice(0, 8).map((s, idx) => (
                            <div
                                key={idx}
                                className="w-2 h-2 bg-cyan-400 rounded-full"
                                title={`${s.seid}: ${s.ue_ip}`}
                            />
                        ))}
                        {sessions.length > 8 && (
                            <span className="text-xs text-slate-500">+{sessions.length - 8}</span>
                        )}
                    </div>
                </div>
            </div>

            {/* Summary Stats Bar */}
            <div className="bg-slate-800/30 rounded-xl p-4 border border-slate-700 flex flex-wrap justify-center gap-8">
                <div className="text-center">
                    <div className="text-sm text-slate-500">Total Packets</div>
                    <div className="text-xl font-bold text-white">{formatNumber(totalPackets)}</div>
                </div>
                <div className="text-center">
                    <div className="text-sm text-slate-500">Total Bytes</div>
                    <div className="text-xl font-bold text-white">{formatBytes(totalBytes)}</div>
                </div>
                <div className="text-center">
                    <div className="text-sm text-slate-500">Combined Throughput</div>
                    <div className="text-xl font-bold text-white">
                        {(metrics.uplink.throughput_mbps + metrics.downlink.throughput_mbps).toFixed(2)} Mbps
                    </div>
                </div>
                <div className="text-center">
                    <div className="text-sm text-slate-500">Last Updated</div>
                    <div className="text-sm text-slate-300">
                        {metrics.uplink.last_updated ? new Date(metrics.uplink.last_updated).toLocaleTimeString() : 'N/A'}
                    </div>
                </div>
            </div>

            {/* Traffic Chart */}
            <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700">
                <h2 className="text-lg font-semibold text-white mb-4">Live Traffic (Last 60s)</h2>
                <TrafficChart metrics={metrics} />
            </div>

            {/* Session Traffic Analysis - NEW */}
            <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700">
                <div className="flex items-center justify-between mb-4">
                    <h2 className="text-lg font-semibold text-white">Per-Session Traffic Analysis</h2>
                    <span className="text-sm text-slate-400">
                        {sessions.length} active session{sessions.length !== 1 ? 's' : ''}
                    </span>
                </div>
                <SessionTrafficChart sessions={sessions} />
            </div>

            {/* Two Column Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Drop Alert Panel */}
                <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700">
                    <h2 className="text-lg font-semibold text-white mb-4">Drop Events</h2>
                    <DropAlertPanel drops={drops} />
                </div>

                {/* Session Table */}
                <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700">
                    <h2 className="text-lg font-semibold text-white mb-4">PDU Sessions (SEID ↔ TEID)</h2>
                    <SessionTable />
                </div>
            </div>

            {/* Network Topology */}
            <div className="bg-slate-800/50 rounded-xl p-5 border border-slate-700">
                <h2 className="text-lg font-semibold text-white mb-4">Network Topology</h2>
                <Topology sessions={sessions} drops={drops} />
            </div>
        </div>
    )
}
