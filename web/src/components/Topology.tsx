import { useEffect, useState } from 'react'
import { Smartphone, Radio, Server, Globe, HelpCircle } from 'lucide-react'
import { SessionInfo, DropStats, fetchTopology, TopologyData, TopologyNode } from '../services/api'

interface TopologyProps {
    sessions: SessionInfo[]
    drops: DropStats
    theme?: 'dark' | 'light'
}

export default function Topology({ sessions, drops, theme = 'dark' }: TopologyProps) {
    const [topology, setTopology] = useState<TopologyData | null>(null)
    const [loading, setLoading] = useState(true)
    const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null)
    const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })

    useEffect(() => {
        const loadTopology = async () => {
            try {
                const data = await fetchTopology()
                setTopology(data)
            } catch (err) {
                console.error('Failed to load topology:', err)
            } finally {
                setLoading(false)
            }
        }

        loadTopology()
        // Refresh every 5 seconds
        const interval = setInterval(loadTopology, 5000)
        return () => clearInterval(interval)
    }, [])

    // Theme-based colors
    const isDark = theme === 'dark'
    const textColor = isDark ? '#e2e8f0' : '#1e293b'
    const subTextColor = isDark ? '#94a3b8' : '#64748b'
    const nodeBg = isDark ? '#1e293b' : '#ffffff'
    const linkColor = isDark ? '#64748b' : '#94a3b8'
    const trafficColor = isDark ? '#4ade80' : '#22c55e'
    const tooltipBg = isDark ? 'bg-slate-800' : 'bg-white'
    const tooltipBorder = isDark ? 'border-slate-700' : 'border-slate-200'
    const tooltipText = isDark ? 'text-slate-200' : 'text-slate-700'

    if (loading && !topology) {
        return <div className="text-center py-10 text-slate-500">Loading topology...</div>
    }

    if (!topology || topology.nodes.length === 0) {
        return <div className="text-center py-10 text-slate-500">No topology data available</div>
    }

    // Group nodes by type
    const nodesByType: Record<string, TopologyNode[]> = {
        'ue': [], 'gnb': [], 'upf': [], 'dn': []
    }
    topology.nodes.forEach(n => {
        if (nodesByType[n.type]) nodesByType[n.type].push(n)
    })

    // Layout configuration
    const width = 800
    const padding = 50

    // Dynamic height based on node count to prevent overlapping
    const maxNodes = Math.max(...Object.values(nodesByType).map(n => n.length))
    const minHeight = 600
    const height = Math.max(minHeight, (maxNodes + 1) * 180)

    const layers = ['ue', 'gnb', 'upf', 'dn']
    const layerX = {
        'ue': width * 0.1,
        'gnb': width * 0.35,
        'upf': width * 0.65,
        'dn': width * 0.9
    }

    // Calculate positions
    const nodePositions: Record<string, { x: number, y: number }> = {}
    
    Object.entries(nodesByType).forEach(([type, nodes]) => {
        const x = layerX[type as keyof typeof layerX]
        const count = nodes.length
        const step = (height - padding * 2) / (count + 1)
        
        nodes.forEach((node, idx) => {
            nodePositions[node.id] = {
                x,
                y: padding + step * (idx + 1)
            }
        })
    })

    // Helper to get icon component
    const getIcon = (type: string, props: any) => {
        switch (type) {
            case 'ue': return <Smartphone {...props} />
            case 'gnb': return <Radio {...props} />
            case 'upf': return <Server {...props} />
            case 'dn': return <Globe {...props} />
            default: return <HelpCircle {...props} />
        }
    }

    // Helper to get node color
    const getColor = (type: string) => {
        switch (type) {
            case 'ue': return '#22c55e' // green-500
            case 'gnb': return '#06b6d4' // cyan-500
            case 'upf': return '#3b82f6' // blue-500
            case 'dn': return '#a855f7' // purple-500
            default: return '#64748b'
        }
    }

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 B'
        const k = 1024
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
        const i = Math.floor(Math.log(bytes) / Math.log(k))
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
    }

    const getNodeStats = (node: TopologyNode) => {
        const stats = []
        
        if (node.type === 'ue') {
            const session = sessions.find(s => s.ue_ip === node.ip || s.ue_ip === node.id)
            if (session) {
                stats.push({ label: 'SUPI', value: session.supi || 'Unknown' })
                stats.push({ label: 'IP', value: session.ue_ip })
                stats.push({ label: 'UL Packets', value: session.packets_ul.toLocaleString() })
                stats.push({ label: 'DL Packets', value: session.packets_dl.toLocaleString() })
                stats.push({ label: 'UL Bytes', value: formatBytes(session.bytes_ul) })
                stats.push({ label: 'DL Bytes', value: formatBytes(session.bytes_dl) })
            } else {
                stats.push({ label: 'Status', value: 'Idle' })
            }
        } else if (node.type === 'upf') {
            const totalPackets = sessions.reduce((acc, s) => acc + s.packets_ul + s.packets_dl, 0)
            const totalBytes = sessions.reduce((acc, s) => acc + s.bytes_ul + s.bytes_dl, 0)
            stats.push({ label: 'Active Sessions', value: sessions.length })
            stats.push({ label: 'Total Drops', value: drops.total, alert: drops.total > 0 })
            stats.push({ label: 'Total Packets', value: totalPackets.toLocaleString() })
            stats.push({ label: 'Total Traffic', value: formatBytes(totalBytes) })
        } else if (node.type === 'gnb') {
            const connectedSessions = sessions.filter(s => s.gnb_ip === node.ip)
            stats.push({ label: 'IP', value: node.ip })
            stats.push({ label: 'Connected UEs', value: connectedSessions.length })
        } else {
            stats.push({ label: 'IP', value: node.ip || 'N/A' })
        }
        
        return stats
    }

    const handleMouseMove = (e: React.MouseEvent) => {
        setTooltipPos({ x: e.clientX + 15, y: e.clientY + 15 })
    }

    return (
        <div className="w-full overflow-hidden">
            <div className="w-full relative">
                <svg 
                    viewBox={`0 0 ${width} ${height}`} 
                    className="w-full h-auto"
                    preserveAspectRatio="xMidYMid meet"
                >
                    <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="28" refY="3.5" orient="auto">
                            <polygon points="0 0, 10 3.5, 0 7" fill={linkColor} />
                        </marker>
                    </defs>

                    {/* Links */}
                    {topology.links.map((link, idx) => {
                        const start = nodePositions[link.source]
                        const end = nodePositions[link.target]
                        if (!start || !end) return null

                        return (
                            <g key={`${link.source}-${link.target}-${idx}`}>
                                <line
                                    x1={start.x}
                                    y1={start.y}
                                    x2={end.x}
                                    y2={end.y}
                                    stroke={linkColor}
                                    strokeWidth="2"
                                    markerEnd="url(#arrowhead)"
                                    strokeDasharray={link.type === 'n3' ? "5,5" : ""}
                                />
                                {/* Traffic Animation */}
                                <circle r="3" fill={trafficColor}>
                                    <animate
                                        attributeName="cx"
                                        from={start.x}
                                        to={end.x}
                                        dur="1.5s"
                                        repeatCount="indefinite"
                                    />
                                    <animate
                                        attributeName="cy"
                                        from={start.y}
                                        to={end.y}
                                        dur="1.5s"
                                        repeatCount="indefinite"
                                    />
                                    <animate
                                        attributeName="opacity"
                                        values="0;1;1;0"
                                        keyTimes="0;0.1;0.9;1"
                                        dur="1.5s"
                                        repeatCount="indefinite"
                                    />
                                </circle>
                                {/* Label */}
                                <text
                                    x={(start.x + end.x) / 2}
                                    y={(start.y + end.y) / 2 - 5}
                                    textAnchor="middle"
                                    fill={subTextColor}
                                    fontSize="10"
                                >
                                    {link.label || link.type.toUpperCase()}
                                </text>
                            </g>
                        )
                    })}

                    {/* Nodes */}
                    {topology.nodes.map((node) => {
                        const pos = nodePositions[node.id]
                        if (!pos) return null
                        let color = getColor(node.type)
                        
                        // Check for drops on UPF
                        const isUpfWithDrops = node.type === 'upf' && drops.total > 0
                        if (isUpfWithDrops) {
                            color = '#ef4444' // red-500
                        }

                        return (
                            <g 
                                key={node.id} 
                                transform={`translate(${pos.x}, ${pos.y})`}
                                onMouseEnter={(e) => {
                                    setHoveredNode(node)
                                    setTooltipPos({ x: e.clientX + 15, y: e.clientY + 15 })
                                }}
                                onMouseMove={handleMouseMove}
                                onMouseLeave={() => setHoveredNode(null)}
                                className="cursor-pointer"
                            >
                                {/* Drop Alert Pulse */}
                                {isUpfWithDrops && (
                                    <circle r="24" fill="none" stroke="#ef4444" strokeWidth="2" opacity="0.5">
                                        <animate attributeName="r" from="24" to="34" dur="1s" repeatCount="indefinite" />
                                        <animate attributeName="opacity" from="0.5" to="0" dur="1s" repeatCount="indefinite" />
                                    </circle>
                                )}

                                {/* Node Circle */}
                                <circle
                                    r="24"
                                    fill={nodeBg}
                                    stroke={color}
                                    strokeWidth="2"
                                    className="transition-all duration-300"
                                />
                                
                                {/* Icon - Centered */}
                                <g transform="translate(-12, -12)">
                                    {getIcon(node.type, { size: 24, color: color })}
                                </g>

                                {/* Label */}
                                <text
                                    x="0"
                                    y="35"
                                    textAnchor="middle"
                                    fill={textColor}
                                    fontSize="12"
                                    fontWeight="bold"
                                >
                                    {node.label}
                                </text>
                                {/* IP Address */}
                                {node.ip && (
                                    <text
                                        x="0"
                                        y="48"
                                        textAnchor="middle"
                                        fill={subTextColor}
                                        fontSize="10"
                                        fontFamily="monospace"
                                    >
                                        {node.ip}
                                    </text>
                                )}
                            </g>
                        )
                    })}
                </svg>

                {/* Tooltip */}
                {hoveredNode && (
                    <div 
                        className={`fixed z-50 p-4 rounded-lg shadow-xl border ${tooltipBg} ${tooltipBorder} pointer-events-none`}
                        style={{ left: tooltipPos.x, top: tooltipPos.y }}
                    >
                        <div className={`font-bold mb-2 ${tooltipText} border-b ${isDark ? 'border-slate-700' : 'border-slate-200'} pb-1`}>
                            {hoveredNode.label}
                        </div>
                        <div className="space-y-1">
                            {getNodeStats(hoveredNode).map((stat, idx) => (
                                <div key={idx} className="flex items-center justify-between gap-4 text-sm">
                                    <span className={subTextColor}>{stat.label}:</span>
                                    <span className={`${stat.alert ? 'text-red-500 font-bold' : tooltipText} font-mono`}>
                                        {stat.value}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                {/* Legend */}
                <div className={`absolute bottom-4 right-4 p-3 rounded-lg border text-xs ${
                    isDark ? 'bg-slate-800/80 border-slate-700' : 'bg-white/80 border-gray-200'
                }`}>
                    <div className={`font-semibold mb-2 ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>Legend</div>
                    <div className="space-y-1">
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-green-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>UE (User Equipment)</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-cyan-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>gNB (Base Station)</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-blue-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>UPF (User Plane)</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="w-3 h-3 rounded-full bg-purple-500"></span>
                            <span className={isDark ? 'text-slate-400' : 'text-gray-600'}>DN (Data Network)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}
