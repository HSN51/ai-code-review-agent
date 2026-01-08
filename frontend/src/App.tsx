import { BrowserRouter as Router, Routes, Route, useNavigate } from 'react-router-dom';
import Layout from './components/Layout';
import { motion } from 'framer-motion';
import { ArrowRight, Code2, GitPullRequest, ShieldCheck, Zap, History as HistoryIcon } from 'lucide-react';
import { cn } from './utils';
import ReviewPage from './pages/ReviewPage';

// Placeholders for pages we will build next
const Dashboard = () => {
  const navigate = useNavigate();

  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-slate-400">
          Welcome back
        </h1>
        <p className="text-slate-400 text-lg max-w-2xl">
          Your AI-powered coding assistant is ready. Analyze snippets or entire pull requests for quality, security, and performance.
        </p>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        <motion.div
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => navigate('/review')}
          className="group relative overflow-hidden rounded-3xl bg-gradient-to-br from-blue-600 to-indigo-600 p-8 cursor-pointer shadow-xl shadow-blue-900/20"
        >
          <div className="absolute top-0 right-0 p-8 opacity-10 group-hover:opacity-20 transition-opacity">
            <Code2 size={120} />
          </div>
          <div className="relative z-10 h-full flex flex-col justify-between space-y-6">
            <div className="p-3 bg-white/10 w-fit rounded-xl backdrop-blur-md">
              <Code2 className="text-white w-8 h-8" />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-white mb-2">Review Code Snippet</h3>
              <p className="text-blue-100">Paste and analyze code instantly for bugs, smells, and security risks.</p>
            </div>
            <div className="flex items-center text-white font-medium group-hover:translate-x-1 transition-transform">
              Start Analysis <ArrowRight className="ml-2 w-5 h-5" />
            </div>
          </div>
        </motion.div>

        <motion.div
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={() => navigate('/pr-review')}
          className="group relative overflow-hidden rounded-3xl bg-[#1e293b] border border-slate-700/50 p-8 cursor-pointer hover:border-slate-600 transition-colors"
        >
          <div className="absolute top-0 right-0 p-8 opacity-[0.03] group-hover:opacity-[0.06] transition-opacity">
            <GitPullRequest size={120} />
          </div>
          <div className="relative z-10 h-full flex flex-col justify-between space-y-6">
            <div className="p-3 bg-indigo-500/10 w-fit rounded-xl">
              <GitPullRequest className="text-indigo-400 w-8 h-8" />
            </div>
            <div>
              <h3 className="text-2xl font-bold text-slate-100 mb-2">Review Pull Request</h3>
              <p className="text-slate-400">Analyze GitHub PRs directly. Get comprehensive reports on changes.</p>
            </div>
            <div className="flex items-center text-indigo-400 font-medium group-hover:translate-x-1 transition-transform">
              Connect Repository <ArrowRight className="ml-2 w-5 h-5" />
            </div>
          </div>
        </motion.div>
      </div>

      <div className="grid md:grid-cols-3 gap-6">
        {[
          {
            icon: ShieldCheck,
            title: "Security First",
            desc: "Detects OWASP vulnerabilities and security risks automatically.",
            color: "text-emerald-400",
            bg: "bg-emerald-500/10"
          },
          {
            icon: Zap,
            title: "Instant Results",
            desc: "Get real-time feedback with sub-second analysis latency.",
            color: "text-amber-400",
            bg: "bg-amber-500/10"
          },
          {
            icon: HistoryIcon,
            title: "Track History",
            desc: "Keep a record of all your analyses and improvement over time.",
            color: "text-purple-400",
            bg: "bg-purple-500/10"
          }
        ].map((feature, i) => {
          const Icon = feature.icon;
          return (
            <div key={i} className="p-6 rounded-2xl bg-[#1e293b]/50 border border-slate-700/50 backdrop-blur-sm">
              <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center mb-4", feature.bg)}>
                <Icon className={cn("w-6 h-6", feature.color)} />
              </div>
              <h4 className="text-lg font-semibold text-slate-200 mb-2">{feature.title}</h4>
              <p className="text-sm text-slate-400">{feature.desc}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PagePlaceholder({ title }: { title: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-[50vh] text-slate-500">
      <h2 className="text-2xl font-bold mb-2">{title}</h2>
      <p>This feature is coming soon.</p>
    </div>
  )
}

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/review" element={<ReviewPage />} />
          <Route path="/pr-review" element={<PagePlaceholder title="PR Review" />} />
          <Route path="/history" element={<PagePlaceholder title="History" />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App
