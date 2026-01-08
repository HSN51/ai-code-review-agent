import { useState, useMemo } from 'react';
import Editor from '@monaco-editor/react';
import { Play, Loader2, AlertTriangle, CheckCircle, Info, XCircle, Shield, Bug, FileCode, ChevronDown, ChevronRight, Calculator } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { reviewCode, type ReviewResult, type Finding } from '../api';
import { cn } from '../utils';

export default function ReviewPage() {
    const [code, setCode] = useState<string>("def hello():\n    print('Hello, World!')");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<ReviewResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    // Group findings by agent
    const groupedFindings = useMemo(() => {
        if (!result) return {};
        const groups: Record<string, Finding[]> = {
            'QualityAgent': [],
            'SecurityAgent': [],
            'TestingAgent': []
        };

        result.findings.forEach(f => {
            if (!groups[f.agent_name]) groups[f.agent_name] = [];
            groups[f.agent_name].push(f);
        });

        return groups;
    }, [result]);

    const handleAnalyze = async () => {
        setLoading(true);
        setError(null);
        setResult(null);
        try {
            const data = await reviewCode(code);
            setResult(data);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex flex-col h-[calc(100vh-8rem)] gap-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white">Code Review</h2>
                    <p className="text-slate-400">Analyze your code snippets instantly.</p>
                </div>
                <button
                    onClick={handleAnalyze}
                    disabled={loading}
                    className="flex items-center gap-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-900/20"
                >
                    {loading ? (
                        <>
                            <Loader2 className="w-5 h-5 animate-spin" />
                            Analyzing...
                        </>
                    ) : (
                        <>
                            <Play className="w-5 h-5 fill-current" />
                            Run Analysis
                        </>
                    )}
                </button>
            </div>

            <div className="flex-1 grid lg:grid-cols-2 gap-6 min-h-0">
                {/* Editor Section */}
                <div className="flex flex-col bg-[#1e293b] rounded-2xl border border-slate-700/50 overflow-hidden shadow-xl">
                    <div className="px-4 py-3 border-b border-slate-700/50 flex justify-between items-center bg-[#1e293b]">
                        <span className="text-sm font-medium text-slate-300">Input Code (Python)</span>
                        <div className="flex items-center gap-2">
                            <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-slate-800/50 text-xs text-slate-400 border border-slate-700/50">
                                <FileCode className="w-3.5 h-3.5" />
                                <span>main.py</span>
                            </div>
                        </div>
                    </div>
                    <div className="flex-1 min-h-[400px]">
                        <Editor
                            height="100%"
                            defaultLanguage="python"
                            theme="vs-dark"
                            value={code}
                            onChange={(val) => setCode(val || "")}
                            options={{
                                minimap: { enabled: false },
                                fontSize: 14,
                                padding: { top: 16 },
                                scrollBeyondLastLine: false,
                                automaticLayout: true,
                                fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                fontLigatures: true,
                            }}
                        />
                    </div>
                </div>

                {/* Results Section */}
                <div className="flex flex-col rounded-2xl min-h-0 overflow-y-auto custom-scrollbar">
                    {error && (
                        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-3">
                            <XCircle className="w-5 h-5 shrink-0" />
                            <p>Error: {error}</p>
                        </div>
                    )}

                    {!result && !loading && !error && (
                        <div className="h-full flex flex-col items-center justify-center text-slate-500 border-2 border-dashed border-slate-700/50 rounded-2xl p-8 bg-[#1e293b]/20">
                            <div className="w-20 h-20 rounded-full bg-slate-800/50 flex items-center justify-center mb-6 ring-4 ring-slate-800/30">
                                <Play className="w-8 h-8 text-slate-600 ml-1" />
                            </div>
                            <h3 className="text-lg font-semibold text-slate-300 mb-2">Ready to analyze</h3>
                            <p className="text-sm max-w-xs text-center">
                                Paste your python code in the editor and click "Run Analysis" to get AI-powered feedback.
                            </p>
                        </div>
                    )}

                    {loading && (
                        <div className="h-full flex flex-col items-center justify-center text-slate-500 rounded-2xl bg-[#1e293b]/30 border border-slate-700/30">
                            <Loader2 className="w-12 h-12 animate-spin text-blue-500 mb-6" />
                            <h3 className="text-lg font-medium text-slate-200 mb-2">Analyzing Code</h3>
                            <div className="flex gap-2">
                                <span className="w-2 h-2 rounded-full bg-blue-500 animate-bounce [animation-delay:-0.3s]"></span>
                                <span className="w-2 h-2 rounded-full bg-blue-500 animate-bounce [animation-delay:-0.15s]"></span>
                                <span className="w-2 h-2 rounded-full bg-blue-500 animate-bounce"></span>
                            </div>
                        </div>
                    )}

                    {result && (
                        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500 pb-8">
                            {/* Score Card */}
                            <div className="p-6 rounded-2xl bg-gradient-to-br from-[#1e293b] to-[#1e293b]/50 border border-slate-700/50 shadow-xl relative overflow-hidden group">
                                <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2 group-hover:bg-blue-500/15 transition-colors" />

                                <div className="flex items-start justify-between relative z-10">
                                    <div>
                                        <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-1">Code Quality Score</h3>
                                        <div className="flex items-baseline gap-2">
                                            <span className={cn("text-4xl font-bold", getScoreTextColor(result.overall_score))}>
                                                {result.overall_score}
                                            </span>
                                            <span className="text-slate-500 font-medium">/ 100</span>
                                        </div>
                                    </div>
                                    <ScoreGauge score={result.overall_score} />
                                </div>

                                <p className="mt-6 text-slate-300 text-sm leading-relaxed border-t border-slate-700/50 pt-4">
                                    {result.summary}
                                </p>
                            </div>

                            {/* Detailed Findings grouped by Agent */}
                            <div className="space-y-4">
                                <h3 className="font-semibold text-slate-200 px-1 flex items-center gap-2">
                                    Analysis Breakdown
                                </h3>

                                <AgentGroup
                                    name="Quality Analysis"
                                    agent="QualityAgent"
                                    findings={groupedFindings['QualityAgent']}
                                    icon={FileCode}
                                    color="blue"
                                />
                                <AgentGroup
                                    name="Security Scan"
                                    agent="SecurityAgent"
                                    findings={groupedFindings['SecurityAgent']}
                                    icon={Shield}
                                    color="emerald"
                                />
                                <AgentGroup
                                    name="Testing Coverage"
                                    agent="TestingAgent"
                                    findings={groupedFindings['TestingAgent']}
                                    icon={Bug}
                                    color="amber"
                                />
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function AgentGroup({ name, findings = [], icon: Icon, color }: any) {
    const [isOpen, setIsOpen] = useState(true);
    const hasFindings = findings.length > 0;

    // Map color to tailwind classes
    const colorStyles: any = {
        blue: { text: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20" },
        emerald: { text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
        amber: { text: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/20" },
    };
    const style = colorStyles[color];

    return (
        <div className="rounded-xl border border-slate-700/50 bg-[#1e293b]/50 overflow-hidden">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="w-full flex items-center justify-between p-4 hover:bg-slate-700/30 transition-colors"
            >
                <div className="flex items-center gap-3">
                    <div className={cn("p-2 rounded-lg", style.bg, style.text)}>
                        <Icon className="w-5 h-5" />
                    </div>
                    <div className="text-left">
                        <h4 className="font-semibold text-slate-200">{name}</h4>
                        <p className="text-xs text-slate-400">
                            {hasFindings ? `${findings.length} issues found` : 'No issues detected'}
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    {!hasFindings && (
                        <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-medium border border-emerald-500/20">
                            <CheckCircle className="w-3.5 h-3.5" />
                            Pass
                        </span>
                    )}
                    {isOpen ? <ChevronDown className="w-5 h-5 text-slate-500" /> : <ChevronRight className="w-5 h-5 text-slate-500" />}
                </div>
            </button>

            <AnimatePresence>
                {isOpen && hasFindings && (
                    <motion.div
                        initial={{ height: 0 }}
                        animate={{ height: "auto" }}
                        exit={{ height: 0 }}
                        className="overflow-hidden"
                    >
                        <div className="p-4 pt-0 space-y-3">
                            {findings.map((finding: Finding) => (
                                <FindingCard key={finding.id} finding={finding} />
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

function ScoreGauge({ score }: { score: number }) {
    // Determine color
    let color = "#10b981"; // emerald
    if (score < 70) color = "#f59e0b"; // amber
    if (score < 40) color = "#ef4444"; // red

    return (
        <div className="relative w-16 h-16 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                {/* Background Ring */}
                <path
                    className="text-slate-700/50"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="3"
                />
                {/* Progress Ring */}
                <path
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke={color}
                    strokeWidth="3"
                    strokeDasharray={`${score}, 100`}
                    className="transition-[stroke-dasharray] duration-1000 ease-out"
                />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
                <Calculator className="w-6 h-6 text-slate-500" />
            </div>
        </div>
    );
}

function getScoreTextColor(score: number) {
    if (score >= 90) return "text-emerald-400";
    if (score >= 70) return "text-amber-400";
    return "text-red-400";
}

function FindingCard({ finding }: { finding: Finding }) {
    const severityConfig = {
        critical: { icon: XCircle, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
        high: { icon: AlertTriangle, color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
        medium: { icon: AlertTriangle, color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/20" },
        low: { icon: Info, color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20" },
        info: { icon: Info, color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/20" },
    };

    const config = severityConfig[finding.severity] || severityConfig.info;
    const Icon = config.icon;

    return (
        <motion.div
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            className={cn("p-4 rounded-xl border bg-[#1e293b] shadow-sm hover:shadow-md transition-shadow", config.border)}
        >
            <div className="flex gap-4">
                <div className={cn("mt-1 p-1.5 rounded-lg h-fit", config.bg)}>
                    <Icon className={cn("w-4 h-4", config.color)} />
                </div>
                <div className="flex-1 space-y-1.5">
                    <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                            <span className={cn("text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-md", config.bg, config.color)}>
                                {finding.severity}
                            </span>
                            <span className="text-xs text-slate-500 font-mono">
                                Line {finding.line_number} • {finding.category}
                            </span>
                        </div>
                    </div>

                    <p className="text-sm font-medium text-slate-200 leading-snug">{finding.message}</p>

                    {finding.suggestion && (
                        <div className="mt-2 text-sm text-slate-400 bg-slate-800/50 p-3 rounded-lg border border-slate-700/50">
                            <span className="text-blue-400 font-medium mr-2 text-xs uppercase tracking-wide">Suggested Fix:</span>
                            {finding.suggestion}
                        </div>
                    )}
                </div>
            </div>
        </motion.div>
    );
}
